"""Execute the native interchip wrapper, callback and future wait offline.

Transport, hash-table services, allocation, reference destruction, TLS/once and
futex services are explicit fixtures. No camera or physical transfer occurs.
"""
import hashlib
import json
import struct
from pathlib import Path
from unicorn import arm64_const as a
from verify_ap_reply_handoff import Handoff,FUTURE,TLS,OBJECT,NODE,VT,INPUT,OUTPUT
from verify_menu import RAM,STACK,STOP,X

HERE=Path(__file__).resolve().parent
TABLE,MUTEX=0x9110118,0x9110150
CONTROL=RAM+0x1800


class Transfer(Handoff):
    def __init__(self,raw,submit=0,callback_arg=0):
        super().__init__(raw,b'')
        self.submit=submit;self.callback_arg=callback_arg
        self.nodes={};self.callback=None;self.cookie=None;self.transfer_args=None
        self.completed=0;self.destructed=[];self.waits=0
        self.write(TABLE,struct.pack('<QQ',RAM+0x1900,8))
        self.write(CONTROL,bytes(32));self.put(CONTROL+8,2)
        self.write(OBJECT,struct.pack('<QQ',VT,0))
        self.write(INPUT,struct.pack('<6I',0x101,0,0x202,0,48124,0))
        self.put(OUTPUT,0xa5a5a5a5)

    def code(self,u,pc,size,unused):
        x=[u.reg_read(X(i)) for i in range(6)]
        if pc in (0x3683324,0x36833e4):
            assert x[:2]==[9,4];self.ret();return
        if pc==0x303c694:
            self.write(x[0],struct.pack('<QQQ',FUTURE,CONTROL,OBJECT))
            self.ret();return
        if pc==0x165fad0:
            assert x[0]==24;self.write(NODE,bytes(24));self.ret(NODE);return
        if pc==0x1794224:
            assert x[0]==MUTEX and not self.held
            self.held.add(MUTEX);self.ret();return
        if pc==0x165ff40:
            assert x[0]==MUTEX and self.held=={MUTEX}
            self.held.clear();self.ret();return
        if pc==0x3514a24:
            assert x[0]==TABLE and self.held=={MUTEX}
            assert not self.nodes
            self.ret(0);return
        if pc==0x3514dc8:
            assert x[0]==TABLE and x[2:4]==[0x101,NODE] and self.held=={MUTEX}
            assert self.word(NODE+8)==0x101
            self.nodes[0x101]=NODE;self.ret();return
        if pc==0x3514b74:
            assert x[0]==TABLE and self.held=={MUTEX}
            self.ret(self.nodes.get(self.word(x[1]),0));return
        if pc==0x3514bac:
            assert x[:2]==[TABLE,NODE] and self.held=={MUTEX}
            assert self.nodes.pop(self.word(NODE+8))==NODE
            self.trace.append('registry_erase_fixture');self.ret();return
        if pc==0x165d290:
            # Actual stack request assembled by 3514f54.
            assert not self.held and self.nodes=={0x101:NODE}
            source,target,n,count,callback,cookie=struct.unpack('<QQIIQQ',u.mem_read(x[0],40))
            assert struct.unpack('<2I',u.mem_read(source,8))==(0x101,0)
            assert struct.unpack('<2I',u.mem_read(target,8))==(0x202,0)
            assert n==48124 and count==1 and callback==0x3514c88
            assert self.word(cookie)==0x101
            self.callback,self.cookie=callback,cookie
            self.transfer_args=(0x101,0x202,n,count)
            self.trace.append('interchip_submit_fixture')
            self.ret(self.submit);return
        if pc==0x165ffc0:
            assert not self.held and x[3:6]==[0,0,0]
            assert self.word(FUTURE+0x10)==0x80000000
            self.waits+=1;self.trace.append('native_wait_without_deadline')
            self.pause('wait');return
        if pc==0x1660550:
            assert x[0]==FUTURE+0x10 and self.word(FUTURE+0x10)==1
            assert self.qword(FUTURE+8)==OBJECT
            self.trace.append('native_ready_notify_fixture');self.ret();return
        if pc==0x165d430:
            assert x[0]==OBJECT+8;self.ret(1);return
        if pc in (0x303ca28,0x303c7ac):
            self.destructed.append(pc);self.ret();return
        if pc==0x36804c8:self.ret();return
        if pc==0x310197c:self.completed+=1
        ranges=[(0x34cb5e8,0x34cb628),(0x3514f54,0x3515288),(0x3514c88,0x3514dc8),
                (0x3514ae8,0x3514b74),(0x310197c,0x3101aa0),(0x303cc78,0x303ccb0),(0x303c448,0x303c47c)]
        if any(lo<=pc<hi for lo,hi in ranges):return
        super().code(u,pc,size,unused)

    def execute(self,deliver=True,spurious=False):
        u=self.u
        saved={X(i):0x11800000+i for i in range(19,30)}
        for reg,value in saved.items():u.reg_write(reg,value)
        u.reg_write(a.UC_ARM64_REG_SP,STACK+0xff00);u.reg_write(a.UC_ARM64_REG_LR,STOP)
        u.reg_write(X(0),INPUT);u.reg_write(X(1),OUTPUT)
        self.ensure(0x34cb5e8,4)
        u.emu_start(0x34cb5e8,STOP,count=30000)
        if not self.submit:
            assert self.stop_reason=='wait' and self.completed==0
            assert self.word(OUTPUT)==0 and self.nodes and not self.held
            if not deliver:return {'waiting':True,'result_already_zero_before_completion':True,'trace':self.trace}
            if spurious:
                self.ret(1);u.emu_start(u.reg_read(a.UC_ARM64_REG_PC),STOP,count=30000)
                assert self.stop_reason=='wait' and self.waits==2 and not self.completed
            sender=u.context_save()
            u.reg_write(a.UC_ARM64_REG_SP,STACK+0x8000)
            u.reg_write(a.UC_ARM64_REG_LR,STOP)
            u.reg_write(X(0),self.callback_arg);u.reg_write(X(1),self.cookie)
            self.phase='callback'
            u.emu_start(self.callback,STOP,count=30000)
            assert u.reg_read(a.UC_ARM64_REG_PC)==STOP and self.completed==1
            assert not self.nodes and not self.held and self.word(FUTURE+0x10)==1
            u.context_restore(sender);self.phase='resume';self.ret(1)
            u.emu_start(u.reg_read(a.UC_ARM64_REG_PC),STOP,count=30000)
        assert u.reg_read(a.UC_ARM64_REG_PC)==STOP
        assert u.reg_read(a.UC_ARM64_REG_SP)==STACK+0xff00
        assert all(u.reg_read(reg)==value for reg,value in saved.items())
        assert not self.nodes and not self.held and self.completed==1
        return {'submit_result':self.submit,'callback_first_argument':self.callback_arg,
                'native_result':self.word(OUTPUT),'future_completion_calls':self.completed,
                'waits':self.waits,'registry_empty':True,'trace':self.trace}


def main():
    raw=(HERE/'dev-menu-03/candidate/appFw.so').read_bytes()
    assert hashlib.sha256(raw).hexdigest()=='5e0741cf58f4125f7b6f5950b5d13d47be025052c9dcc1a799e2ce004cd32c93'
    cases=[]
    for arg in (0,1,0xffffffff):
        n=Transfer(raw,callback_arg=arg);r=n.execute();assert r['native_result']==0
        cases.append(r)
    for status in (1,2,3,4,5,6,7,8,0xffffffff):
        n=Transfer(raw,submit=status);r=n.execute();assert r['waits']==0
        cases.append(r)
    spurious=Transfer(raw).execute(spurious=True);assert spurious['waits']==2 and spurious['native_result']==0
    waiting=Transfer(raw).execute(deliver=False)
    report={'status':'AP_NATIVE_INTERCHIP_WAIT_CALLBACK_SCOPE_VERIFIED','camera_io':False,
            'ap_sha256':hashlib.sha256(raw).hexdigest(),'cases':cases,'no_callback':waiting,'spurious_wake':spurious,
            'source_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
                (Path(__file__).name,'verify_ap_reply_handoff.py','verify_menu.py')},
            'limitations':['Interchip transport, registry services, object creation/destruction, TLS, once and futex services are fixtures.',
                           'No physical transfer or cancellation/quiescence guarantee is established.',
                           'The callback first argument is tested as opaque input; its API meaning is not inferred.',
                           'No timeout or production AP owner is installed by this evidence script.']}
    path=HERE/'lifecycle-dev/ap-transfer-scope.json';path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cases':len(cases),'missing_callback_waits':True}))


if __name__=='__main__':main()
