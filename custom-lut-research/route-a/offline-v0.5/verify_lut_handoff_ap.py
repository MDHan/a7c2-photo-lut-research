"""Actual AArch64 state/filter execution and host timeout/grant races.

Private replies are fixtures: no CP lease implementation is claimed.
"""
import ctypes
import hashlib
import json
import struct
import subprocess
import threading
from pathlib import Path
import build_lut_handoff_ap as builder
from verify_menu import Native, RAM, STACK, STOP, X, a
from verify_ap_reply_handoff import Handoff

HERE=builder.HERE
Q=lambda i:getattr(a,'UC_ARM64_REG_Q'+str(i))


def packet(id=1, op=1, status=0, generation=17, session=(0x1234,0x5678)):
    return struct.pack('<BBHIIHBBIIII',1,0,0x4155,id,0x504c5554,1,op,status,
                       *session,generation,0)


class Core(Native):
    def __init__(self, raw, recipe, bias=0):
        super().__init__(raw)
        self.recipe=recipe;self.bias=bias
        if bias:
            self.segments=[{**s,'p_vaddr':s['p_vaddr']+bias} for s in self.segments]
        self.base=recipe['code']+bias;self.state=recipe['state']+bias
        self.write(self.state,bytes(16))
    def call(self, name, *args):
        return self.run(self.base+self.recipe['symbols'][name],(self.state,*args),
                        [(self.base,self.base+self.recipe['payload_size'])])
    def receive(self,p):
        self.write(RAM+0x6000,p or b'\0')
        return self.call('lh_ap_receive',RAM+0x6000,len(p))
    def snapshot(self):return bytes(self.u.mem_read(self.state,16))
    def phase(self):return self.word(self.state)&15
    def opened(self):
        assert self.call('lh_ap_open',0x1234,0x5678)==1
        assert self.call('lh_ap_begin')==1


class Bridge(Core):
    def code(self,u,pc,size,unused):
        if pc in (0x3531598+self.bias,0x35316cc+self.bias):
            self.target=pc-self.bias;u.emu_stop();return
        if pc==0x165e770+self.bias:
            assert u.reg_read(X(0))==RAM+0x6000
            for i in range(19):u.reg_write(X(i),0xabcdef0000+i)
            for i in range(32):u.reg_write(Q(i),(1<<127)+i)
            u.reg_write(a.UC_ARM64_REG_NZCV,0xf0000000)
            u.reg_write(a.UC_ARM64_REG_FPCR,0)
            u.reg_write(a.UC_ARM64_REG_FPSR,0)
            self.ret(self.length);return
        if pc==0x3531594+self.bias or self.base<=pc<self.base+self.recipe['payload_size']:
            return
        super().code(u,pc,size,unused)
    def dispatch(self,p):
        u=self.u;self.length=len(p);self.target=None
        self.write(RAM+0x6000,p or b'\0')
        registers={X(i):0x22220000+i for i in range(31)}
        registers[X(19)]=RAM+0x6000
        vectors={Q(i):(0x1122334455667788<<64)+i for i in range(32)}
        for reg,value in {**registers,**vectors}.items():u.reg_write(reg,value)
        u.reg_write(a.UC_ARM64_REG_SP,STACK+0xff00)
        u.reg_write(a.UC_ARM64_REG_NZCV,0xa0000000)
        u.reg_write(a.UC_ARM64_REG_FPCR,0x400000)
        u.reg_write(a.UC_ARM64_REG_FPSR,0x8000000)
        self.ensure(0x3531594+self.bias,4)
        u.emu_start(0x3531594+self.bias,STOP,count=10000)
        assert self.target is not None
        if self.target==0x3531598:registers[X(0)]=p[0] if p else 0
        assert all(u.reg_read(reg)==value for reg,value in {**registers,**vectors}.items())
        assert u.reg_read(a.UC_ARM64_REG_SP)==STACK+0xff00
        assert u.reg_read(a.UC_ARM64_REG_NZCV)==0xa0000000
        assert u.reg_read(a.UC_ARM64_REG_FPCR)==0x400000
        assert u.reg_read(a.UC_ARM64_REG_FPSR)==0x8000000
        return self.target


def core_cases(raw,r):
    records=[]
    for bias in (0,0x10000000,0x7100000000):
        h=Core(raw,r,bias)
        assert h.call('lh_ap_begin')==0
        assert h.call('lh_ap_open',0,0)==0
        h.opened()
        assert h.call('lh_ap_open',0x99,0x88)==0
        assert h.call('lh_ap_write',1)==0
        assert h.call('lh_ap_request',RAM+0x7000)==32
        expected=bytearray(packet());expected[0]=5;struct.pack_into('<I',expected,24,0)
        assert bytes(h.u.mem_read(RAM+0x7000,32))==expected
        assert h.receive(packet(status=1))==1 and h.phase()==2
        assert h.receive(packet())==1 and h.phase()==4
        assert h.word(h.state+12)==17
        assert h.call('lh_ap_write',2)==0 and h.call('lh_ap_write',1)==1
        assert h.call('lh_ap_cancel',1)==0 and h.phase()==5
        assert h.call('lh_ap_begin')==0
        assert h.call('lh_ap_written',1,1)==1 and h.phase()==6
        assert h.call('lh_ap_request',RAM+0x7000)==32
        request=bytes(h.u.mem_read(RAM+0x7000,32))
        assert request[14]==2 and struct.unpack_from('<I',request,24)[0]==17
        assert h.receive(packet(op=2))==1 and h.phase()==1
        assert h.call('lh_ap_begin')==2
        before=h.snapshot();h.receive(packet());assert h.snapshot()==before
        assert h.call('lh_ap_cancel',2)==1 and h.phase()==7
        h.receive(packet(id=2));assert h.phase()==7
        assert h.call('lh_ap_write',2)==0
        h.receive(packet(id=2,op=3,status=2));assert h.phase()==7
        h.receive(packet(id=2,op=3));assert h.phase()==1
        assert h.call('lh_ap_begin')==3
        records.append({'bias':hex(bias),'normal_publish_and_late_grant_after_cancel':'passed'})
    for failure in ('acquire','transfer','commit','commit_timeout'):
        h=Core(raw,r);h.opened()
        if failure=='acquire':h.receive(packet(status=2))
        else:
            h.receive(packet());assert h.call('lh_ap_write',1)==1
            h.call('lh_ap_written',1,int(failure!='transfer'))
            if failure=='commit':h.receive(packet(op=2,status=2))
            if failure=='commit_timeout':assert h.call('lh_ap_cancel',1)==1
        assert h.phase()==7 and h.call('lh_ap_begin')==0
        assert h.call('lh_ap_request',RAM+0x7000)==32
        assert h.u.mem_read(RAM+0x7000+14,1)==b'\x03'
        h.receive(packet(op=3));assert h.phase()==1
        records.append({'failure':failure,'retained_until_cancel_ack':'passed'})
    h=Core(raw,r);h.opened()
    h.put(h.state,0xfffffff1)
    before=h.snapshot();assert h.call('lh_ap_begin')==0 and h.snapshot()==before
    records.append({'id_exhaustion_no_wrap':'passed'})
    malformed=[]
    mutations=[(1,1),(12,2),(13,1),(14,0),(14,4),(15,3),(16,0),(20,0),(28,1),(4,2)]
    inputs=[packet()[:length] for length in range(32)]+[packet()+b'\0']
    for off,value in mutations:
        p=bytearray(packet());p[off]=value;inputs.append(bytes(p))
    for p in inputs:
        h=Core(raw,r);h.opened();before=h.snapshot();owned=h.receive(p)
        assert h.snapshot()==before and h.call('lh_ap_write',1)==0
        malformed.append({'length':len(p),'packet':p.hex(),'owned':owned})
    return records,malformed


def bridge_cases(raw,r):
    records=[]
    for bias in (0,0x10000000,0x7100000000):
        for kind in ('grant','stale','short','bad_version','other_magic','native_4160'):
            h=Bridge(raw,r,bias);h.opened()
            p=bytearray(packet())
            if kind=='stale':struct.pack_into('<I',p,4,77)
            if kind=='short':p=p[:12]
            if kind=='bad_version':p[12]=99
            if kind=='other_magic':p[8]=0
            if kind=='native_4160':struct.pack_into('<H',p,2,0x4160)
            target=h.dispatch(bytes(p))
            owned=kind not in ('other_magic','native_4160')
            assert target==(0x35316cc if owned else 0x3531598)
            assert h.phase()==(4 if kind=='grant' else 2)
            records.append({'bias':hex(bias),'case':kind,'target':hex(target),
                            'all_gpr_simd_flags_preserved':True})
    # Complete the previously verified native sender/receiver path through the
    # new hook: ordinary 4160 still uses its original future and result parser.
    class Forward(Handoff):
        def code(self,u,pc,size,unused):
            if r['code']<=pc<r['code']+r['payload_size']:return
            super().code(u,pc,size,unused)
    reply=struct.pack('<BBHIIHHHH',1,0,0x4160,0x2222,0xf000,640,480,0,0)
    h=Forward(raw,reply);result=h.execute()
    assert result['parsed_output']==[0,640,480,0]
    records.append({'native_4160_full_sender_receiver_preserved':True})
    return records


def interrupted_publication(raw,r):
    class Paused(Core):
        armed=False
        def code(self,u,pc,size,unused):
            if self.armed and self.word(self.state)==0x13:
                self.armed=False;u.emu_stop();return
            super().code(u,pc,size,unused)
    h=Paused(raw,r);h.opened();u=h.u
    h.write(RAM+0x6000,packet())
    h.allowed=[(h.base,h.base+r['payload_size'])]
    u.reg_write(X(0),h.state);u.reg_write(X(1),RAM+0x6000);u.reg_write(X(2),32)
    u.reg_write(a.UC_ARM64_REG_SP,STACK+0xff00);u.reg_write(a.UC_ARM64_REG_LR,STOP)
    h.armed=True
    u.emu_start(h.base+r['symbols']['lh_ap_receive'],STOP,count=5000)
    assert h.word(h.state)==0x13 and not h.armed
    publisher=u.context_save()
    # Use a disjoint stack for the cancellation context; do not reset or
    # overwrite the paused callback's stack/register state.
    u.reg_write(X(0),h.state);u.reg_write(X(1),1)
    u.reg_write(a.UC_ARM64_REG_SP,STACK+0x8000);u.reg_write(a.UC_ARM64_REG_LR,STOP)
    u.emu_start(h.base+r['symbols']['lh_ap_cancel'],STOP,count=5000)
    assert u.reg_read(X(0))==0 and h.word(h.state)==0x13
    u.context_restore(publisher)
    u.emu_start(u.reg_read(a.UC_ARM64_REG_PC),STOP,count=5000)
    assert h.word(h.state)==0x14 and h.word(h.state+12)==17
    assert h.call('lh_ap_cancel',1)==1 and h.word(h.state)==0x17
    assert h.call('lh_ap_write',1)==0
    return {'native_aarch64_pause_after_grant_claim':True,'cancel_retries_after_update':True}


def concurrency():
    out=builder.OUT/'handoff-host.dylib'
    cmd=['/usr/bin/clang','-dynamiclib','-O2','-Wall','-Wextra','-Werror',
         str(HERE/'lut_handoff_ap.c'),'-o',str(out)]
    subprocess.run(cmd,check=True,capture_output=True,text=True)
    lib=ctypes.CDLL(str(out))
    class State(ctypes.Structure):_fields_=[(n,ctypes.c_uint32) for n in ('control','lo','hi','generation')]
    for name,args in [('lh_ap_open',[ctypes.POINTER(State),ctypes.c_uint32,ctypes.c_uint32]),
                      ('lh_ap_begin',[ctypes.POINTER(State)]),
                      ('lh_ap_cancel',[ctypes.POINTER(State),ctypes.c_uint32]),
                      ('lh_ap_receive',[ctypes.POINTER(State),ctypes.c_void_p,ctypes.c_uint32]),
                      ('lh_ap_written',[ctypes.POINTER(State),ctypes.c_uint32,ctypes.c_uint32]),
                      ('lh_ap_write',[ctypes.POINTER(State),ctypes.c_uint32])]:
        fn=getattr(lib,name);fn.argtypes=args;fn.restype=ctypes.c_uint32
    for attempt in range(64):
        state=State();assert lib.lh_ap_open(ctypes.byref(state),0x1234,0x5678)==1
        assert lib.lh_ap_begin(ctypes.byref(state))==1
        start=threading.Barrier(3);p=ctypes.create_string_buffer(packet());errors=[]
        def receive():
            try:start.wait();assert lib.lh_ap_receive(ctypes.byref(state),p,32)==1
            except BaseException as error:errors.append(repr(error))
        def cancel():
            try:start.wait();lib.lh_ap_cancel(ctypes.byref(state),1)
            except BaseException as error:errors.append(repr(error))
        workers=[threading.Thread(target=receive),threading.Thread(target=cancel)]
        for worker in workers:worker.start()
        start.wait()
        for worker in workers:worker.join(timeout=5);assert not worker.is_alive()
        assert not errors,errors
        # Retry is required when the first cancellation met transient UPDATE.
        assert lib.lh_ap_cancel(ctypes.byref(state),1)==1
        assert state.control==0x17 and lib.lh_ap_write(ctypes.byref(state),1)==0
        lib.lh_ap_receive(ctypes.byref(state),p,32)
        assert state.control==0x17
    for attempt in range(64):
        state=State();lib.lh_ap_open(ctypes.byref(state),0x1234,0x5678)
        lib.lh_ap_begin(ctypes.byref(state))
        p=ctypes.create_string_buffer(packet());lib.lh_ap_receive(ctypes.byref(state),p,32)
        start=threading.Barrier(3);results={};errors=[]
        def compete(name):
            try:
                start.wait()
                results[name]=getattr(lib,name)(ctypes.byref(state),1)
            except BaseException as error:errors.append(repr(error))
        workers=[threading.Thread(target=compete,args=(name,)) for name in ('lh_ap_write','lh_ap_cancel')]
        for worker in workers:worker.start()
        start.wait()
        for worker in workers:worker.join(timeout=5);assert not worker.is_alive()
        assert not errors,errors
        assert sum(results.values())==1
        if results['lh_ap_write']:
            assert state.control==0x15 and results['lh_ap_cancel']==0
            assert lib.lh_ap_written(ctypes.byref(state),1,0)==1
        assert state.control==0x17 and lib.lh_ap_begin(ctypes.byref(state))==0
    return {'host_timeout_grant_races':64,'host_writer_cancel_races':64,
            'command':cmd,'sha256':hashlib.sha256(out.read_bytes()).hexdigest()}


def main():
    raw,r=builder.make();again,r2=builder.make()
    assert raw==again and r==r2
    core,malformed=core_cases(raw,r)
    bridges=bridge_cases(raw,r)
    interrupted=interrupted_publication(raw,r)
    races=concurrency()
    report={'status':'AP_REPLY_FILTER_COMPONENT_OFFLINE_VERIFIED_NOT_FLASHABLE','camera_io':False,
            'in_memory_ap_sha256':r['in_memory_ap_sha256'],'recipe_sha256':hashlib.sha256((builder.OUT/'recipe.json').read_bytes()).hexdigest(),
            'core_cases':core,'malformed_reply_cases':malformed,'bridge_cases':bridges,'concurrency':races,
            'interrupted_publication':interrupted,
            'limitations':['CP grant/cancel replies are fixtures; no CP lease/reader gate exists yet',
                           'AP session bootstrap, upload owner and deadlines are not connected',
                           'BSS ELF extent and emulator zero mapping checked, not real dynamic loader or WBI',
                           'host concurrency is not a proof of camera scheduling or DMA visibility',
                           'new bridge consumes up to 704 extra stack bytes; real receiver stack headroom unverified'],
            'source_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
                            ('verify_lut_handoff_ap.py','verify_ap_reply_handoff.py','verify_menu.py')}}
    (builder.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'core_cases':len(core),'malformed_cases':len(malformed),
                      'bridge_cases':len(bridges),'host_races':128,'status':report['status']}))


if __name__=='__main__':main()
