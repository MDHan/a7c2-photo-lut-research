"""Actual native worker loop with new completion and dispatch bridges.

Code placement, startup state, OS, DMA and interrupt timing are fixtures.
"""
import json
import struct
from unicorn import UC_PROT_READ,UC_PROT_EXEC
from unicorn import arm_const as ar
import build_lut_dma_worker as build
import verify_queue_allocation_guard as queue
import verify_queue_completion as native
import verify_lut_handoff_cp as lease

v=queue.v


class Integrated(native.Worker):
    def __init__(self,cp,payload,recipe,messages,modes):
        super().__init__(cp,'success')
        self.recipe=recipe
        self.placement=json.loads((build.parent.parent.OUT/'recipe.json').read_text())
        self.messages=messages
        self.modes=modes
        self.results=[]
        self.frees=0
        self.current=None
        self.u.mem_map(build.CODE,4096)
        self.u.mem_write(build.CODE,payload)
        self.u.mem_protect(build.CODE,4096,UC_PROT_READ|UC_PROT_EXEC)
        v.put(self.u,build.STATE,0)
        v.put(self.u,build.GATE,0)

    def code(self,u,pc,size,unused):
        args=[u.reg_read(v.reg(i)) for i in range(4)]
        if build.CODE<=pc<build.CODE+self.recipe['code_size']:return
        p=self.placement
        if (p['left_code']<=pc<p['left_code']+p['left_size'] or
                p['right_code']<=pc<p['right_code']+p['right_size']):return
        if pc==0x5653a8:
            assert args[0]==0x2ae085a and args[2]==0xffffffff
            if self.receives==len(self.messages):
                u.emu_stop();return
            self.current=self.messages[self.receives]
            self.mode=self.modes[self.receives]
            self.receives+=1
            u.mem_write(native.release.BUFFER,self.current)
            v.put(u,args[1],native.release.BUFFER)
            self.ret();return
        if pc==0x565300:
            assert args[:2]==[0x2ae085a,native.release.BUFFER]
            self.frees+=1;self.ret();return
        if pc==0xb82c80:
            self.results.append(args[0] if args[0]<0x80000000 else args[0]-0x100000000)
        if pc==0x5353f4:
            assert args[1]==native.DMA_DESC
            kind,channel=struct.unpack_from('<I',self.current)[0],struct.unpack_from('<I',self.current,8)[0]
            actual,count,entries=struct.unpack('<3I',u.mem_read(args[0],12))
            assert actual==channel
            assert count=={1:48,2:3,3:1}[kind]
            self.timeline.append('dma_descriptor_boundary')
            self.ret();return
        if pc==0x56309c and args[1]==1000 and self.mode=='missing_completion':
            self.waits.append(1000);self.ret();return
        if pc==native.TRAMPOLINE and self.mode=='success_then_timeout':
            assert self.context is not None
            u.context_restore(self.context);self.context=None
            self.timeline.append('completion_then_wait_failure')
            self.ret(-1);return
        if (0xb82d7c<=pc<0xb82dbe or 0xb82e00<=pc<0xb82e5a or
                0xb8336c<=pc<0xb833f4):return
        super().code(u,pc,size,unused)

    def loop(self):
        self.u.reg_write(ar.UC_ARM_REG_SP,v.SP)
        self.u.emu_start(0xb82c23,v.STOP,count=150000)
        assert self.u.reg_read(ar.UC_ARM_REG_PC)==0x5653a8
        assert self.receives==self.frees==len(self.messages)
        assert len(self.results)==len(self.messages)


def messages(cp,art):
    n=queue.Producer(cp,0,15,0)
    for address in (v.STATE,v.DESC,v.RES):v.put(n.u,address,0)
    n.u.mem_write(v.PENDING,b'\0')
    n.apply(art);n.apply(art)
    assert [struct.unpack_from('<I',m)[0] for m in n.queued]==([1,3,2] if art else [1,2])
    return n.queued


def verify(cp,payload,r):
    cases=[]
    faults=[]
    for art in (False,True):
        batch=messages(cp,art)
        success=Integrated(cp,payload,r,batch*3,['success']*len(batch)*3)
        success.loop()
        assert success.results==[0]*len(batch)*3
        assert success.callback_results==[0,0,0]
        assert v.word(success.u,build.STATE)==v.word(success.u,build.GATE)==0
        cases.append({'art':art,'case':'three_batches','messages':len(batch)*3,
                      'results':success.results,'callbacks':success.callback_results})
        for where in range(len(batch)):
            for mode,expected in [('dma_error',-6),('timeout',-7),('initial_wait_failure',-20),
                                  ('registration_failure',-20),('submission_failure',-20),
                                  ('missing_completion',-20),('success_then_timeout',-7)]:
                modes=['success']*len(batch);modes[where]=mode
                n=Integrated(cp,payload,r,batch,modes)
                n.loop()
                assert n.results==[0]*where+[expected]+[-20]*(len(batch)-where-1),(art,where,mode,n.results)
                assert n.callback_results==[expected if where==len(batch)-1 else -20]
                assert v.word(n.u,build.STATE)==3 and v.word(n.u,build.GATE)&0x20000000
                submitted=n.timeline.count('submit_dma')
                assert submitted<=where+1
                before=list(n.callback_results)
                for status in (0,1,0):n.call(native.ISR,status)
                assert n.callback_results==before
                assert v.word(n.u,build.STATE)==3 and n.timeline.count('submit_dma')==submitted
                cases.append({'art':art,'failed_index':where,'mode':mode,'results':n.results,
                              'callbacks':list(n.callback_results),'dma_submissions':submitted,
                              'late_completions_ignored':3,'fault_retained':True})
        # Reuse the terminal-fault machine: no native dispatch may replace the
        # capture pointer, including message types outside the user-LUT trio.
        saved_callback=v.word(n.u,native.CALLBACK_GLOBAL)
        saved_submissions=n.timeline.count('submit_dma')
        pointer=v.RAM+0x900
        for kind in range(6):
            msg=bytearray(56);struct.pack_into('<I',msg,0,kind);struct.pack_into('<I',msg,12,0x4e89f1)
            n.u.mem_write(pointer,bytes(msg))
            assert n.call(r['addresses']['lut_dma_dispatch'],pointer)==(-20&0xffffffff)
            assert n.callback_results[-1]==-20
            assert v.word(n.u,native.CALLBACK_GLOBAL)==saved_callback
            assert n.timeline.count('submit_dma')==saved_submissions
        core=n.placement['core_addresses'];state=n.placement['state']
        assert n.call(core['lh_cp_open'],state,0x1234,0x5678,17)==1
        assert n.call(core['lh_cp_reader_begin'],state)==0
        n.u.mem_write(lease.INPUT,lease.request())
        n.u.mem_write(lease.OUTPUT,b'\xa5'*40)
        assert n.call(core['lh_cp_request'],state,lease.INPUT,32,lease.OUTPUT)==2
        assert n.u.mem_read(lease.OUTPUT+15,1)==b'\2'
        assert n.u.mem_read(lease.OUTPUT+32,8)==b'\xa5'*8
        faults.append({'art':art,'rejected_dispatch_types':list(range(6)),
                       'completion_pointer_preserved':True,'new_reader_rejected':True,
                       'new_write_permission_error':True})
    return {'cases':cases,'fault_gate_cases':faults}


def main():
    cp,payload,r=build.make()
    tests=verify(cp,payload,r)
    report={'status':'NATIVE_DMA_RESULT_AND_FAULT_DISPATCH_EXPERIMENT_VERIFIED_NOT_FLASHABLE',
            'camera_io':False,'recipe_sha256':build.b.sha((build.OUT/'recipe.json').read_bytes()),
            'payload_sha256':build.b.sha(payload),**tests,
            'source_sha256':{name:build.b.sha((build.HERE/name).read_bytes()) for name in
                             ('verify_lut_dma_worker.py','verify_queue_completion.py',
                              'verify_queue_allocation_guard.py','verify_lut_ownership.py','verify_resource_release.py',
                              'verify_lut_handoff_cp.py')},
            'limitations':['Payload uses emulator-only address 0x80000; state initialization and mapping are fixtures, not bootable firmware.',
                           'Native worker, dispatcher, DMA-wait function, ISR and user-LUT application callback execute; OS/DMA/timing are fixtures.',
                           'Application notification is deferred to worker context; only actual user-LUT callbacks are verified here.',
                           'All five direct wait call sites and the worker dispatch call are instrumented; indirect/external callers are not exhaustively excluded.',
                           'Fault recovery is cold-only; reader leases, real upload/session hooks, DMA quiescence and WBI are incomplete.',
                           'Late completions are checked after terminal fault; arbitrary stale hardware completion during a later successful transfer is not proven impossible.']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cases':len(tests['cases'])}))


if __name__=='__main__':main()
