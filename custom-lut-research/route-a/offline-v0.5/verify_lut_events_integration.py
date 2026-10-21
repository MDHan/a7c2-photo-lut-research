"""Real AP task -> file/mapping/copy -> session/CP permission -> publication.

Only local frozen files are read. Kernel, OSAL, filesystem and physical DMA are
explicit services. Both protocol peers execute compiled code at real addresses.
"""
import gc
import json
import struct
from pathlib import Path
from unicorn import arm64_const as a
from verify_menu import RAM,STACK,STOP,X
from verify_upload_guards import Guarded
from verify_lut_upload import RANGES
from verify_lut_handoff_ap import bridge_cases
import verify_lut_ingress_placement as oldcp
import verify_lut_events_cp as cpboot
import verify_lut_cp_ingress as ipc
import build_lut_events_cp as cpbuild
import build_lut_events_owner as build
import verify_sequence_scheduling as sequence

b=build.b
AP_MESSAGE,REPLY=RAM+0x18000,RAM+0x19000
TRAMP=STOP+0x100


class SessionIPC(oldcp.PlacedIPC):
    def open(self):pass  # Production HELLO must initialize the core, not a fixture.
    def __init__(self,bundle,cold_machine=None):
        self.pool=[]
        if cold_machine is None:ipc.IPC.__init__(self,bundle)
        else:super().__init__(bundle,cold_machine)
    def code(self,u,pc,size,unused):
        args=[u.reg_read(ipc.v.reg(i)) for i in range(4)]
        if pc==0x566378:
            assert args[0]==0x1b20c00 and 64<=args[1]<=4352
            if self.queue_running and self.send_fault=='allocation':self.ret(0);return
            pointer=self.pool.pop() if self.pool else self.ipc_heap
            if pointer==self.ipc_heap:self.ipc_heap+=0x1200
            assert self.ipc_heap<ipc.AREA+0x10000
            self.ipc_allocations[pointer]=args[1];u.mem_write(pointer,b'\xa5'*args[1])
            ipc.v.put(u,args[3],0);self.ret(pointer);return
        if pc==0x566528:
            assert args[0]==0x1b20c00 and self.ipc_allocations.pop(args[1])==args[2]
            self.frees.append(args[1]);self.pool.append(args[1]);u.mem_write(args[1],b'\xdd'*args[2]);self.ret();return
        super().code(u,pc,size,unused)
    def release_reply(self,pointer):
        self.call(0x565300,ipc.AP_PORT,pointer)


def cp_bundle():
    raw,code,r=cpbuild.make();off=r['publication_address']-cpbuild.CODE
    pub=code[off:off+r['publication_size']]
    off=(r['ingress_address']&~1)-cpbuild.CODE
    adapter=code[off:r['restore_code_start']-cpbuild.CODE]
    return (raw,code,r,pub,{'symbols':r['publication_symbols']},adapter,{'code_bytes':len(adapter)})


class Owner(Guarded):
    def __init__(self,raw,r,peer,special=False,fault=None,delay=20,cancel_at=None):
        self.cancel_at=cancel_at;self.cancelled=False;self.r=r;self.peer=peer;self.clock=0;self.delay=delay;self.dma=None
        self.inbox=[];self.schedule=None;self.old_callback=None;self.old_callback_word=None;self.owned_alloc=False
        self.protocol=[];self.published_messages=[];self.received=[];self.dropped=0
        self.entropy=bytes.fromhex('b16d6a290f7c3194');self.entropy_at=0
        self.owner_fault=fault;self.copy_times=[];self.dma_submits=[];self.cookies=[];self.secondary=[]
        manifest=json.loads((b.HERE/'dev-menu-03/manifest.json').read_text())
        Guarded.__init__(self,raw,manifest,b'\x52'*(48124 if special else 48000),special=special,
                         fault=fault if fault in ('file_open','map_open','mmap') else None)
        self.state=r['state'];self.ensure(self.state,r['state_bytes']);assert self.u.mem_read(self.state,r['state_bytes'])==bytes(r['state_bytes'])
    def run(self,entry,args=(),allowed=()):
        if entry not in (0x34289a8,0x3209d48):return super().run(entry,args,allowed)
        self.allowed=list(allowed)+[(0x2850000,0x28a0000)]
        for i,value in enumerate(args):self.u.reg_write(X(i),value)
        saved={X(i):0x22220000+i for i in range(19,30)}
        for reg,value in saved.items():self.u.reg_write(reg,value)
        self.u.reg_write(a.UC_ARM64_REG_SP,STACK+0xff00);self.u.reg_write(a.UC_ARM64_REG_LR,STOP)
        self.ensure(entry,4);self.u.emu_start(entry,STOP,count=4000000)
        assert self.u.reg_read(a.UC_ARM64_REG_PC)==STOP,hex(self.u.reg_read(a.UC_ARM64_REG_PC))
        assert self.u.reg_read(a.UC_ARM64_REG_SP)==STACK+0xff00
        assert all(self.u.reg_read(reg)==value for reg,value in saved.items())
        return self.u.reg_read(X(0))
    def phase(self):return self.word(self.state)&15
    def result(self):
        n=self.word(self.state+28);return n if n<0x80000000 else n-0x100000000
    def transfer_state(self):return self.word(self.state+200)&3
    def inject(self,u,pc,kind,first,cookie=None):
        assert self.schedule is None
        self.schedule=(u.context_save(),kind,cookie)
        u.reg_write(a.UC_ARM64_REG_SP,STACK+0x7000)
        u.reg_write(a.UC_ARM64_REG_LR,TRAMP)
        if kind=='reply':
            packet,pointer=first
            self.write(REPLY,packet);self.received.append(packet)
            u.reg_write(X(19),REPLY);u.reg_write(a.UC_ARM64_REG_PC,0x3531594)
        elif kind=='cancel':
            u.reg_write(X(0),first);u.reg_write(a.UC_ARM64_REG_PC,self.r['symbols']['lh_owner_cancel_request'])
        else:
            callback,arg=first;u.reg_write(X(0),0);u.reg_write(X(1),arg)
            u.reg_write(a.UC_ARM64_REG_PC,callback)
    def resume_sleep(self,u):
        context,kind,pointer=self.schedule;self.schedule=None
        if kind=='reply':self.peer.release_reply(pointer)
        u.context_restore(context);self.ret(0)
    def code(self,u,pc,size,unused):
        args=[u.reg_read(X(i)) for i in range(6)]
        if self.schedule and pc==0x35316cc:
            assert self.schedule[1]=='reply';self.resume_sleep(u);return
        if self.schedule and pc==TRAMP:
            assert self.schedule[1] in ('dma','old','cancel')
            if self.schedule[1]=='dma':assert self.transfer_state()==2
            elif self.schedule[1]=='old':assert self.word(self.state+200)==self.old_callback_word
            self.resume_sleep(u);return
        if pc==self.r['symbols']['lh_monotonic']+12:
            assert args[0]==1 and u.reg_read(X(8))==113
            if self.owner_fault=='clock':u.reg_write(X(0),0xffffffffffffffff)
            else:
                self.write(args[1],struct.pack('<qq',self.clock//1000,(self.clock%1000)*1000000));u.reg_write(X(0),0)
            u.reg_write(a.UC_ARM64_REG_PC,pc+4);return
        if pc==0x165d3c0 and self.string(args[0])=='/dev/urandom':
            assert args[1]==0
            self.entropy_at=0
            self.ret(0xffffffffffffffff if self.owner_fault=='entropy_open' else 42);return
        if pc==0x165d4b0:
            assert args[0]==42 and args[2]<=8
            data=self.entropy[self.entropy_at:self.entropy_at+args[2]]
            if self.owner_fault=='entropy_short':data=data[:1] if self.entropy_at==0 else b''
            self.entropy_at+=len(data);self.write(args[1],data or b'\0');self.ret(len(data));return
        if pc==0x165f430 and args[0]==42:self.ret(-1&0xffffffff if self.owner_fault=='entropy_close' else 0);return
        if pc==0x1660540:self.ret(0x718);return
        if pc==0x1660060:
            assert args[0]==0x90030001 and args[2] in (32,128) and args[3]==1 and not self.owned_alloc
            assert self.qword(args[1])==0
            if self.owner_fault=='allocation':self.ret(-1&0xffffffff);return
            self.write(args[1],struct.pack('<Q',AP_MESSAGE));self.write(AP_MESSAGE,b'\xa5'*args[2])
            self.owned_alloc=True;self.ret(0);return
        if pc==0x165d600:
            assert args[:2]==[AP_MESSAGE,0x80020002] and self.owned_alloc;self.ret();return
        if pc==0x165ead0:
            assert args[:2]==[0x90030001,AP_MESSAGE] and self.owned_alloc
            op=u.mem_read(AP_MESSAGE+14,1)[0];n=128 if op==2 else 32
            packet=bytes(u.mem_read(AP_MESSAGE,n));self.protocol.append(packet)
            if self.owner_fault in ('send','free'):
                self.ret(-1&0xffffffff);return
            self.owned_alloc=False
            before=len(self.peer.sent);replies=self.peer.deliver(packet,native_copy=True)
            for (pointer,_),reply in zip(self.peer.sent[before:],replies,strict=True):
                drop=self.owner_fault=='no_replies' or (self.owner_fault=='no_commit' and op==2) or (self.owner_fault=='lost_commit' and op==2 and not self.dropped)
                if drop:self.peer.release_reply(pointer);self.dropped+=1
                else:self.inbox.append((reply,pointer))
            self.ret(0);return
        if pc==0x1660350:
            assert args[:2]==[0x90030001,AP_MESSAGE] and self.owned_alloc
            if self.owner_fault=='free':self.ret(-1&0xffffffff)
            else:self.owned_alloc=False;self.ret(0)
            return
        if pc==0x165e770:
            assert args[0]==REPLY and self.schedule is not None
            self.ret(32);return
        if pc==0x165ea70:
            assert args[0]==10000
            self.clock+=10
            if self.cancel_at is not None and not self.cancelled and self.clock>=self.cancel_at:
                self.cancelled=True;self.inject(u,pc,'cancel',self.word(self.state)>>4);return
            if self.old_callback:
                callback,cookie=self.old_callback;self.old_callback=None
                self.old_callback_word=self.word(self.state+200)
                self.inject(u,pc,'old',(callback,cookie));return
            if self.dma and self.clock>=self.dma[0]:
                _,callback,cookie=self.dma;self.dma=None
                self.inject(u,pc,'dma',(callback,cookie));return
            if self.inbox:
                packet,pointer=self.inbox.pop(0)
                self.inject(u,pc,'reply',(packet,pointer),pointer);return
            self.ret();return
        if pc==0x165d290:
            assert self.phase()==5 and self.word(self.state+16)==1
            source,target,n,count,callback,cookie=struct.unpack('<QQIIQQ',u.mem_read(args[0],40))
            assert source==self.state+144 and target==self.state+152
            nonce=self.qword(self.state+4)
            assert cookie==(nonce+self.word(self.state+204))&0xffffffffffffffff
            assert self.transfer_state()==1 and count==1
            assert struct.unpack('<2I',u.mem_read(source,8))==(0x101,0)
            assert struct.unpack('<2I',u.mem_read(target,8))==(0x202,0)
            self.dma_submits.append(self.clock);self.cookies.append((callback,cookie))
            if self.owner_fault=='old_callback' and len(self.cookies)>1:self.old_callback=self.cookies[-2]
            if self.owner_fault=='transfer_reject':self.ret(3);return
            self.dma=None if self.delay is None else (self.clock+self.delay,callback,cookie)
            self.ret(0);return
        if pc in (0x165d270,0x165d3e0) and args[0]==0x10005000:
            assert self.phase()==5 and self.word(self.state+16)==1
            assert self.peer.bits()==0
            assert ipc.v.word(self.peer.u,self.peer.placement['state']+4)&0xc0000000==0xc0000000
            self.copy_times.append(self.clock)
        if pc==0x34c6418:
            assert self.word(self.state+44)==1 and self.phase()==1
            self.secondary.append(self.clock);self.ret();return
        if (self.r['core_layout']['code']<=pc<self.r['code']+self.r['code_size'] or
                pc in (0x34289a8,0x3531594)):
            return
        super().code(u,pc,size,unused)
    def execute_task(self,lut=3,exists=1):
        self.task(0x311a63c,2,12,lut,exists)
        ptr=self.run(0x2887b48)
        if lut>=3:self.write(ptr+lut-3,bytes([int(self.special)]))
        self.timeline.clear();self.messages.clear()
        assert self.run(0x34289a8,(RAM+0x4000,),[(0x34289a8,0x34289f0)]+RANGES)==1
        assert self.schedule is None and not self.word(self.state+16)
        return self.result()


class WorkerOwner(Owner,sequence.Worker):
    def __init__(self,*args,**kwargs):
        self.held=set();self.worker_events=[];self.task_locks=None
        self.destructed=self.notified=0;self.terminator_injected=False
        self.header=sequence.MANAGER+0x310
        super().__init__(*args,**kwargs)
    def code(self,u,pc,size,unused):
        if pc==0x34289a8:
            self.task_locks=sorted(self.held);self.worker_events.append('real_owned_lut_task_started')
        super().code(u,pc,size,unused)
    def execute_worker(self,system=2):
        self.task(0x311a63c,system,12,3,1)
        ptr=self.run(0x2887b48);self.write(ptr,bytes([int(self.special)]))
        self.write(sequence.TASK+8,struct.pack('<Q',sequence.IMPL))
        self.write(sequence.IMPL,bytes(0x1b8));self.put(sequence.IMPL+8,0x1bc)
        self.write(sequence.MANAGER,bytes(0x4500))
        head=sequence.MANAGER+0x44d0
        self.write(head,struct.pack('<QQQ',head,head,0));self.put(self.header+8,0)
        self.enqueue_fixture(sequence.TASK)
        allowed=RANGES+[(0x34289a8,0x34289f0),(0x3209d48,0x3209f10),
                        (0x303c794,0x303c7ac),(0x303cb84,0x303cc78)]
        self.run(0x3209d48,(sequence.MANAGER,self.header),allowed)
        assert self.result()==0 and self.peer.publications==1
        assert self.notified==self.destructed==1 and self.task_locks==[] and not self.held,(self.notified,self.destructed,self.task_locks,self.held)
        assert self.terminator_injected and len(self.secondary)==1
        return {'system':system,'special':self.special,'real_worker_notifies_and_destroys_once':True,
                'queue_locks_not_held_during_upload':True}


def protocol_scope(bundle):
    def wire(op=4,id=0,generation=0,lo=0x1234,hi=0x5678):
        return struct.pack('<8I',0x41550005,id,0x504c5554,1|(op<<16),lo,hi,generation,0)
    def deliver(peer,packet):
        before=len(peer.sent);replies=peer.deliver(packet,native_copy=True)
        for pointer,_ in peer.sent[before:]:peer.release_reply(pointer)
        return replies
    p=SessionIPC(bundle)
    assert deliver(p,wire())[0][15]==0
    token=p.core('lh_cp_reader_begin');assert token
    before=bytes(p.u.mem_read(p.placement['state'],148))
    assert deliver(p,wire())[0][15]==0
    assert deliver(p,wire(lo=0x1235))[0][15]==2
    assert bytes(p.u.mem_read(p.placement['state'],148))==before
    assert p.core('lh_cp_reader_end',token)==1
    malformed=[]
    for n in (0,3,4,8,12,16,31,33):malformed.append((wire()+b'\0')[:n])
    for offset,value in ((1,1),(4,1),(12,2),(13,1),(15,1),(24,1),(28,1)):
        data=bytearray(wire());data[offset]=value;malformed.append(bytes(data))
    malformed.append(wire(lo=0,hi=0))
    for packet in malformed:
        q=SessionIPC(bundle);assert deliver(q,packet)==[]
        assert ipc.v.word(q.u,q.placement['state']+8)==0 and not q.original_dispatches
    q=SessionIPC(bundle);assert deliver(q,wire())[0][15]==0
    assert deliver(q,wire(op=1,id=1))[0][15]==0
    clear=bytearray(96);struct.pack_into('<4I',clear,0,0x41550005,1,0x62a,0xffffffff)
    header=wire(op=2,id=1,generation=17)
    for offset in (16,20,24,28):
        bad=bytearray(clear);bad[offset]=1
        assert deliver(q,header+bad)==[] and not q.publications
    assert deliver(q,header+clear)[0][15]==0 and q.publications==1
    assert bytes(q.u.mem_read(ipc.v.G+0x68,24))==bytes(24)
    reply=deliver(q,wire(op=3,id=1,generation=17))[0]
    assert reply[15]==0 and reply[28]==1
    return {'malformed_hello':len(malformed),'session_collision_rejected':True,
            'duplicate_hello_preserves_active_reader':True,'malformed_clear':4,
            'native_clear_and_committed_cancel_marker':True}


def main():
    raw,r=build.make();raw2,r2=build.make();assert raw==raw2 and r==r2
    bundle=cp_bundle();cp,code,cr,*_=bundle
    cold_cases=[];flows=[];failures=[];recoveries=[];workers=[]
    protocol=protocol_scope(bundle)
    receive_regression=bridge_cases(raw,r['core_layout'])
    probe=Owner(raw,r,SessionIPC(bundle))
    assert probe.run(0x30210c8,(0,),RANGES)==0 and not probe.copy_times
    probe.write(RAM+0x1a000,b'\xa5'*4)
    probe.run(r['symbols']['lh_owner_transfer'],(0,RAM+0x1a000))
    assert probe.word(RAM+0x1a000)==2 and not probe.dma_submits
    for mode in (False,True):
        u,cold=cpboot.cold(cp,code,cr,mode)
        n=Owner(raw,r,SessionIPC(bundle,u),special=mode)
        assert n.execute_task()==0 and n.phase()==1 and n.peer.publications==1 and len(n.secondary)==1
        assert n.entropy_at==8 and n.word(n.state+24)==1
        assert n.peer.core('lh_cp_reader_begin')  # published buffer accepts readers
        token=n.peer.bits();assert token.bit_count()==1
        # Return the actual epoch-bearing token through its reader record.
        slot=(token&-token).bit_length()-1
        epoch=ipc.v.word(n.peer.u,n.peer.placement['state']+32+slot*4)&0x07ffffff
        assert n.peer.core('lh_cp_reader_end',(epoch<<5)|slot)==1
        assert n.execute_task(lut=2)==0 and n.peer.publications==2 and n.phase()==1
        assert bytes(n.peer.u.mem_read(ipc.v.G+0x68,24))==bytes(24)
        assert n.execute_task(exists=0)==0 and n.peer.publications==3
        cold_cases.append({'mode':mode,'boot':cold,'real_task_session_upload_builtin_and_delete':True,
                           'real_entropy_read_and_protocol_open':True,'secondary_after_ack_only':True})
    for art in (False,True):
        for lut in (3,18):
            n=Owner(raw,r,SessionIPC(bundle),special=art)
            assert n.execute_task(lut)==0 and n.peer.publications==1
            assert len(n.copy_times)==2 and len(n.dma_submits)==1
            assert n.execute_task(lut)==0 and n.peer.publications==2
            flows.append({'art':art,'slot':lut,'two_uploads':True,'session_open_once':n.entropy_at==8})
    for system in (2,3):
        n=WorkerOwner(raw,r,SessionIPC(bundle),special=system==3)
        workers.append(n.execute_worker(system))
    for fault in ('entropy_open','entropy_short','clock','allocation','send','no_replies','file_open','map_open','mmap','transfer_reject'):
        n=Owner(raw,r,SessionIPC(bundle),fault=fault)
        result=n.execute_task();assert result<0 and not n.peer.publications and not n.secondary
        assert n.phase() in (1,0) and not n.owned_alloc
        if fault in ('entropy_open','entropy_short','clock','allocation','send','no_replies','file_open','map_open','mmap'):
            assert not n.copy_times
        n.owner_fault=None;n.fault=None
        assert n.execute_task()==0 and n.peer.publications==1 and len(n.secondary)==1
        failures.append({'fault':fault,'error':result,'no_early_publication_or_secondary':True,'next_task_recovers':True})
        gc.collect()
    for fault in ('lost_commit','no_commit'):
        n=Owner(raw,r,SessionIPC(bundle),fault=fault)
        assert n.execute_task()==0 and n.peer.publications==1 and len(n.secondary)==1
        assert n.dropped and sum(p[14]==2 for p in n.protocol)>1
        recoveries.append({'fault':fault,'native_publications':1,'secondary_once':True,
                           'cancel_ack_resolves_already_committed':fault=='no_commit'})
    n=Owner(raw,r,SessionIPC(bundle));token=n.peer.core('lh_cp_reader_begin');assert token
    assert n.execute_task()<0 and not n.copy_times and not n.secondary
    assert n.peer.bits() and n.peer.core('lh_cp_reader_end',token)==1
    assert n.execute_task()==0
    recoveries.append({'reader_busy_timeout_then_cancel_and_retry':True})
    n=Owner(raw,r,SessionIPC(bundle),delay=6500)
    assert n.execute_task()==-110 and n.phase()==5 and n.transfer_state()==1 and not n.peer.publications
    copied=len(n.copy_times);n.delay=20
    # The next task waits for the old callback, cancels that transaction,
    # then acquires a fresh permission before any new shared-buffer write.
    assert n.execute_task()==0 and n.peer.publications==1 and len(n.copy_times)==copied+2
    assert n.clock>=6500 and n.phase()==1
    n.owner_fault='old_callback'
    assert n.execute_task()==0 and n.peer.publications==2 and n.transfer_state()==2
    recoveries.append({'transfer_timeout_returns_without_stack_cookie':True,
                       'late_callback_drains_before_cancel_and_next_copy':True,'old_callback_cannot_complete_new_ticket':True})
    n=Owner(raw,r,SessionIPC(bundle),delay=None)
    assert n.execute_task()==-110 and n.phase()==5 and n.transfer_state()==1
    copied=len(n.copy_times);assert n.execute_task()<0 and len(n.copy_times)==copied and not n.peer.publications
    recoveries.append({'missing_callback_retains_write_quarantine':True,'next_task_cannot_overwrite':True})
    n=Owner(raw,r,SessionIPC(bundle),delay=100,cancel_at=40)
    assert n.execute_task()==-125 and n.phase()==5 and n.transfer_state()==1 and not n.secondary
    n.cancel_at=None;n.delay=20
    assert n.execute_task()==0 and n.peer.publications==1 and n.phase()==1
    recoveries.append({'explicit_cancel_during_pending_transfer':True,'late_completion_then_cancel_and_new_task':True})
    n=Owner(raw,r,SessionIPC(bundle),fault='entropy_close')
    assert n.execute_task()<0 and n.word(n.state+20)==1 and not n.copy_times
    count=len(n.protocol);n.owner_fault=None
    assert n.execute_task()<0 and len(n.protocol)==count
    recoveries.append({'entropy_close_failure_does_not_leak_repeated_opens':True})
    n=Owner(raw,r,SessionIPC(bundle),fault='free')
    assert n.execute_task()<0 and n.word(n.state+20)==1 and n.owned_alloc
    count=len(n.protocol);n.owner_fault=None
    assert n.execute_task()<0 and len(n.protocol)==count and not n.copy_times
    recoveries.append({'failed_free_is_fatal_without_force_reset':True})
    report={'status':'REAL_UPLOAD_TASK_SESSION_DEADLINE_CANCEL_OFFLINE_VERIFIED_NOT_FLASHABLE',
            'camera_io':False,'full_image_written':False,'ap_sha256':r['in_memory_ap_sha256'],
            'cp_sha256':cr['in_memory_cp_sha256'],'ap_recipe_sha256':b.sha((build.OUT/'recipe.json').read_bytes()),
            'cp_recipe_sha256':b.sha((cpbuild.OUT/'recipe.json').read_bytes()),'cold_cases':cold_cases,
            'receiver_regression':receive_regression,'unowned_copy_and_transfer_rejected':True,'protocol_scope':protocol,'flows':flows,'workers':workers,'failures':failures,'recovery':recoveries,'rebuild_identical':True,
            'source_sha256':{name:b.sha((b.HERE/name).read_bytes()) for name in
                (Path(__file__).name,'verify_lut_events_cp.py','verify_lut_ingress_placement.py',
                 'verify_lut_cp_ingress.py','verify_lut_cp_publication.py','verify_lut_handoff_ap.py','verify_sequence_scheduling.py','verify_upload_guards.py','verify_lut_upload.py','verify_menu.py')},
            'limitations':['OS, entropy, filesystem, mapping, physical OSAL transport and interchip transfer remain service fixtures.',
                           'This matrix covers select_lut; native cancel/delete/reset are verified by the separate menu-events report.',
                           'Monotonic deadlines are bounded instruction paths, not physical scheduling or kernel-service latency guarantees.',
                           'A missing hardware completion is quarantined; no unsupported hardware abort or forced release is invented.',
                           'The async driver rejection/no-late-operation contract follows the native wrapper but remains a hardware/API boundary.',
                           'Private session is cold-process-only; a different nonce is rejected without takeover. WBI and installer remain incomplete.',
                           'Central reader/reapply checks are in a separate report. External ownership, complete UI/persistence and actual JPEG output remain unproven.']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cold':len(cold_cases),'flows':len(flows),
                      'failure_recovery':len(failures),'recovery_cases':len(recoveries),'workers':len(workers),'protocol':protocol}),flush=True)


if __name__=='__main__':main()
