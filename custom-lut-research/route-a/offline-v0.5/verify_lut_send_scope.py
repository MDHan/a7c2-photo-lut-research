"""Execute native 4155 sender past the former transport capture boundary.

Allocation, serialization and IPC send are fixtures. No CP response is injected.
Verify whether this caller requests/waits for one, not actual IPC delivery.
"""
import hashlib
import json
from pathlib import Path
import struct
from verify_upload_guards import Guarded
from verify_menu import RAM, X

HERE=Path(__file__).resolve().parent
FUTURE,OBJECT,PACKET=RAM+0x17000,RAM+0x18000,RAM+0x19000


class Sender(Guarded):
    def __init__(self,raw,manifest,special):
        super().__init__(raw,manifest,bytes([0x52])*(48124 if special else 48000),special=special)
        self.send_events=[];self.held=set();self.future_results=[]

    def code(self,u,pc,size,unused):
        args=[u.reg_read(X(i)) for i in range(6)]
        if pc==0x35358b8:
            assert args[0]==0x90030001 and args[2]==96
            assert args[3:]==[0,0,0]
            self.messages.append(bytes(u.mem_read(args[1],96)))
            self.send_events.append({'sender_arguments':args[:1]+args[2:]})
        if 0x35358b8<=pc<0x3535b5c or 0x34e6700<=pc<0x34e6730 or 0x303cb68<=pc<0x303cb84:
            return
        if pc==0x34f4fec:
            assert args[1]==0
            self.write(FUTURE,bytes(64))
            self.write(args[0],struct.pack('<QQ',FUTURE,0))
            self.send_events.append('future_construction_fixture')
            self.ret();return
        if pc==0x165fad0:
            assert args[0]==0x20
            self.write(OBJECT,bytes(0x20));self.ret(OBJECT);return
        if pc==0x1660560:
            assert args[0]==OBJECT
            self.ret();return
        if pc==0x3599b68:
            assert args[1:4]==[96,0x90030001,0x80020002]
            message=bytes(u.mem_read(args[0],96))
            assert message==self.messages[-1]
            self.write(PACKET,message)
            self.send_events.append('serialization_fixture')
            self.ret(PACKET);return
        if pc==0x1794224:
            assert args[0]==0x91165a0 and args[0] not in self.held
            self.held.add(args[0]);self.ret();return
        if pc==0x1794280:
            mutex=self.qword(args[0]);assert mutex in self.held
            self.held.remove(mutex);self.ret();return
        if pc==0x165ead0:
            assert args[:2]==[0x90030001,PACKET]
            assert self.held=={0x91165a0}
            self.send_events.append('ipc_send_success_fixture')
            self.ret(0);return
        if pc==0x34f4f4c:
            raise AssertionError('unexpected response wait')
        if pc==0x303c7ac:
            assert self.qword(args[0])==0
            self.ret();return
        if pc==0x34f3474:
            self.future_results.append(self.word(FUTURE+0x10))
            self.send_events.append('future_destructor_fixture')
            self.ret();return
        super().code(u,pc,size,unused)


def main():
    folder=HERE/'dev-menu-03'
    raw=(folder/'candidate/appFw.so').read_bytes()
    digest=hashlib.sha256(raw).hexdigest()
    assert digest=='5e0741cf58f4125f7b6f5950b5d13d47be025052c9dcc1a799e2ce004cd32c93'
    manifest=json.loads((folder/'manifest.json').read_text())
    cases=[]
    for system in (2,3):
        for special in (False,True):
            n=Sender(raw,manifest,special)
            message=n.execute(system=system)
            assert n.future_results==[0] and not n.held
            assert n.send_events[-1]=='future_destructor_fixture'
            assert struct.unpack_from('<H',message,2)[0]==0x4155
            cases.append({'system':system,'special':special,'events':n.send_events,
                          'future_readiness_at_cleanup':n.future_results,
                          'response_injected':False,'response_wait_called':False,
                          'upload_task_returned':True})
    report={'status':'LUT_SENDER_RESPONSE_SCOPE_OFFLINE_VERIFIED','camera_io':False,
            'ap_sha256':digest,'cases':cases,
            'conclusion':'4155 upload caller does not request a response buffer or wait for CP completion',
            'limitations':['future allocation and destruction, packet serialization and IPC send are fixtures',
                           'file access, mapping and interchip transfer inherit upload fixtures',
                           'no send failure, real transport, CP acknowledgment or hardware completion is tested'],
            'source_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
                             ('verify_lut_send_scope.py','verify_upload_guards.py','verify_lut_upload.py','verify_menu.py')}}
    out=HERE/'lifecycle-dev/lut-send-scope.json'
    out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'cases':len(cases),'response_wait_called':False,'report':str(out)}))


if __name__=='__main__':main()
