"""Offline AP dependency lookup and still-record event-loop scope.

Do not infer a per-photo fence from the lifetime of a sequence object.
No devices, real OS waits, event-handler bodies, or uploads are executed.
"""
import hashlib
import io
import json
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as ar
from verify_menu import Native, RAM, STACK, STOP, X
from verify_sequence_scheduling import Heap, MANAGER

HERE=Path(__file__).resolve().parent
AP_SHA='5e0741cf58f4125f7b6f5950b5d13d47be025052c9dcc1a799e2ce004cd32c93'
TASK,IMPL,NODE,CONFIG,EVENT=RAM+0x5000,RAM+0x7000,RAM+0x8000,RAM+0xa000,RAM+0xb000
RUN,END=0x34adfc8,0x34ae51c
DIAGNOSTICS={0x36e9310,0x36804c8,0x165e250,0x165ea70,0x35aa4b4}


class Lookup(Heap,Native):
    def __init__(self,raw):
        super().__init__(raw)
        self.held=set()

    def code(self,u,pc,size,unused):
        if pc==0x1794224:
            mutex=u.reg_read(X(0));assert mutex not in self.held
            self.held.add(mutex);self.ret();return
        if pc==0x1794280:
            mutex=self.qword(u.reg_read(X(0)));assert mutex in self.held
            self.held.remove(mutex);self.ret();return
        super().code(u,pc,size,unused)

    def setup(self,queued_id=None,running_id=None):
        header=MANAGER+0x320+2*0x90
        self.write(MANAGER,bytes(0x4500))
        self.write(header,struct.pack('<QQQ',header,header,0))
        for address,impl,seq in [(TASK,IMPL,queued_id),(TASK+0x20,IMPL+0x200,running_id)]:
            self.write(address,struct.pack('<QQ',0,impl))
            self.write(impl,bytes(0x1b8))
            self.put(impl+8,0 if seq is None else seq)
        if queued_id is not None:
            self.write(header,struct.pack('<QQQ',NODE,NODE,1))
            self.write(NODE,struct.pack('<QQQ',header,header,TASK))
        if running_id is not None:self.write(MANAGER+0x398+2*0x90,struct.pack('<Q',TASK+0x20))


class EventLoop(Native):
    def __init__(self,raw,handlers):
        super().__init__(raw)
        self.handlers=handlers
        self.handled=[];self.freed=[];self.locked=False
        self.visits=0;self.rearm=False

    def code(self,u,pc,size,unused):
        args=[u.reg_read(X(i)) for i in range(3)]
        if pc==0x34ae158:
            self.visits+=1
            if self.visits==2 and not self.rearm:u.emu_stop();return
        if pc==0x34adff8:
            u.emu_stop();return
        if pc==0x2f3a954:
            assert not self.locked and self.qword(args[0])==TASK+0x2a0
            self.locked=True;self.ret();return
        if pc==0x17b0adc:
            assert self.locked
            self.locked=False;self.ret();return
        if pc==0x34a84a8:
            assert args[0]==TASK+0x2d0
            self.write(TASK+0x2e0,struct.pack('<Q',EVENT+16))
            self.ret();return  # deque pop boundary
        if pc in self.handlers:
            if pc not in DIAGNOSTICS:assert args[0]==TASK,(hex(pc),hex(args[0]))
            self.handled.append(pc)
            self.ret();return  # body of capture/record/event handler not executed
        if pc==0x2dafe14:
            if self.rearm:self.write(TASK+0x3cc,b'\0')
            self.freed.append(args[0]);self.ret();return
        if pc in (0x285ef78,0x286d158,0x2866064,0x28798cc,0x286374c,0x286829c):
            self.ret(CONFIG);return
        if pc==0x165d3e0:
            assert args[2]==0x150
            self.write(args[0],bytes(self.u.mem_read(args[1],args[2])))
            self.ret(args[0]);return
        if pc in (0x2e06cc0,0x2e068cc,0x2d450f0,0x36829c4,0x3682a04):
            self.ret();return
        super().code(u,pc,size,unused)

    def one(self,event,rearm=False,active=True):
        self.rearm=rearm
        self.write(TASK,bytes(0x1200));self.write(CONFIG,bytes(0x150))
        self.write(TASK+0x3cc,bytes([int(active)]))
        self.write(TASK+0x2e0,struct.pack('<Q',EVENT))
        self.write(TASK+0x300,struct.pack('<Q',EVENT+16))
        self.write(EVENT,struct.pack('<IIQ',event,0,CONFIG))
        frame=STACK+0xfe00
        self.write(frame,bytes(0xc0));self.write(frame+0xa0,struct.pack('<Q',TASK+0x2a0))
        for register,value in [(19,TASK),(21,frame+0xa0),(22,0x4c5f4d1),
                               (24,0x3704878),(26,TASK+0x2a0),(29,frame),(30,STOP)]:
            self.u.reg_write(X(register),value)
        self.u.reg_write(ar.UC_ARM64_REG_SP,frame)
        self.allowed=[(RUN,END)]
        self.ensure(0x34ae158,4)
        self.u.emu_start(0x34ae158,STOP,count=3000)
        pc=self.u.reg_read(ar.UC_ARM64_REG_PC)
        assert pc==(0x34adff8 if rearm or not active else 0x34ae158)
        assert not self.locked
        assert self.freed==([CONFIG] if active else [])
        return {'event':event,'active':active,'event_cleared_run_flag_fixture':rearm,
                'handlers':[hex(x) for x in self.handled],'stop_pc':hex(pc),
                'returned_to_sequence_worker':False}


def inspect(raw):
    n=Native(raw)
    # Read through ELF VA mapping, including the data segment's file offset.
    vtable=0x5b47d38
    assert n.qword(vtable-8)==0x5b47cf8
    assert n.qword(0x5b47cf8+8)==0x4c5f470
    n.ensure(0x4c5f470,32)
    assert bytes(n.u.mem_read(0x4c5f470,31)).split(b'\0')[0]==b'N5model21sequence_still_recordE'
    assert n.qword(vtable+16)==RUN
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    instructions=list(decoder.disasm(raw[RUN:END],RUN))
    assert len(instructions)*4==END-RUN
    assert not any(i.mnemonic=='ret' for i in instructions)
    direct=[];indirect=[]
    for ins in instructions:
        if ins.mnemonic=='br':indirect.append(ins.address)
        if ins.mnemonic=='b' or ins.mnemonic.startswith('b.') or ins.mnemonic in ('cbz','cbnz','tbz','tbnz'):
            target=int(ins.op_str.split('#')[-1],16)
            assert RUN<=target<END,(hex(ins.address),hex(target))
            direct.append((hex(ins.address),hex(target)))
    assert indirect==[0x34ae260]
    handlers=set();dispatch=[]
    n.ensure(0x4c5f418,82)
    for event,offset in enumerate(struct.unpack('<41h',n.u.mem_read(0x4c5f418,82))):
        target=0x34ae264+offset*4
        assert RUN<=target<END
        calls=[]
        for ins in decoder.disasm(raw[target:min(target+256,END)],target):
            if ins.mnemonic=='bl':
                dest=int(ins.op_str[1:],16)
                if dest not in (0x3682a04,0x2dafe14):calls.append(dest)
            if ins.mnemonic=='b':break
        assert calls or target==0x34ae270
        handlers.update(calls)
        dispatch.append({'event':event,'target':hex(target),'calls':[hex(x) for x in calls]})
    return handlers,{'vtable':hex(vtable),'rtti_name':'N5model21sequence_still_recordE',
                     'run':hex(RUN),'end':hex(END),'ret_instructions':0,
                     'normal_branch_targets_within_function':direct,'event_dispatch':dispatch}


def main():
    raw=(HERE/'dev-menu-03/candidate/appFw.so').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==AP_SHA
    handlers,structure=inspect(raw)
    lookups=[]
    for queued,running,expected in [(None,None,0),(0x4bd,None,TASK),
                                   (None,0x4bd,TASK+0x20),(0x4bd,0x4bd,TASK),
                                   (0x1bc,0x4bd,TASK+0x20),(0x1bc,0x1bc,0)]:
        n=Lookup(raw);n.setup(queued,running)
        result=n.run(0x31a752c,(MANAGER,0x4bd),[(0x31a752c,0x31a75f8),(0x303c794,0x303c7a0)])
        assert result==expected and not n.held
        lookups.append({'queued':queued,'running':running,'selected_pointer':hex(result)})
    cases=[]
    for event in range(41):
        for rearm in (False,True):
            case=EventLoop(raw,handlers).one(event,rearm)
            assert case['handlers']==structure['event_dispatch'][event]['calls']
            cases.append(case)
    cases.append(EventLoop(raw,handlers).one(0,active=False))
    report={'status':'CAPTURE_SEQUENCE_SCOPE_OFFLINE_VERIFIED','camera_io':False,
            'ap_sha256':AP_SHA,'structure':structure,'lookup_cases':lookups,'event_cases':cases,
            'conclusion':'still-record sequence normal event completion is not sequence-worker completion',
            'limitations':['capture handler bodies, property services, deque operations and OS locks are fixtures',
                           'event-loop tests start after native run setup with an explicit saved-frame fixture',
                           'exceptions, task cancellation and device shutdown are not modeled',
                           'no DMA/VFX/JPEG completion or shared-buffer exclusion is established'],
            'source_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
                             ('verify_capture_sequence_scope.py','verify_menu.py','verify_sequence_scheduling.py')}}
    out=HERE/'lifecycle-dev/capture-sequence-scope.json'
    out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'lookup_cases':len(lookups),'event_cases':len(cases),'report':str(out)}))


if __name__=='__main__':main()
