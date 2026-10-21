"""Native enqueue, retained leases, worker completion and CP permission tests."""
import json
import struct
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_EXEC
import build_lut_reader_placement as build
import verify_lut_dma_placement as coldcheck
import verify_lut_dma_worker as runtime
import verify_queue_allocation_guard as queue
import verify_lut_handoff_cp as lease
import verify_lut_ownership as ownership

v=queue.v
B=build.base


class Owner(queue.Producer):
    def __init__(self,cp,payload,r,fail_at=0,enqueue_fail=0,mask=15,mode=0,cold_machine=None):
        self.worker=None;self.code_address=r.get('code_address',B.CODE);self.r=r;self.enqueue_fail=enqueue_fail;self.free_calls=0
        self.gates=[]
        self.placement=json.loads((B.parent.parent.OUT/'recipe.json').read_text())
        super().__init__(cp,fail_at,mask,mode)
        if cold_machine is None:
            self.u.mem_write(self.code_address,payload)
            v.put(self.u,B.STATE,0)
            self.u.mem_write(self.placement['state'],bytes(148))
        else:
            previous=self.u;self.u=cold_machine
            # Explicit existing OS/registry/driver-address fixtures only;
            # never replace the copied code or the private cleared states.
            spans=[(v.RAM,0x10000),(ownership.REGISTRY,32),(ownership.SHADOW,16),(0xceedb0,32),
                   (0xe9515c,28),(0xe9d550,28),(0xe9d588,56)]
            spans += [(a,4) for a in (v.STATE,v.DESC,v.RES,v.TOKEN,v.PENDING)]
            for a,n in spans:self.u.mem_write(a,bytes(previous.mem_read(a,n)))
            assert self.u.mem_read(self.code_address,len(payload))==payload
            assert self.u.mem_read(self.placement['state'],148)==bytes(148)
            assert v.word(self.u,B.STATE)==0
            self.u.hook_add(UC_HOOK_CODE,self.code)
            self.u.hook_add(UC_HOOK_MEM_WRITE,self.memory)
            self.u.hook_add(UC_HOOK_MEM_READ,self.memory)
        self.u.mem_protect(self.code_address,4096,UC_PROT_READ|UC_PROT_EXEC)

    def code(self,u,pc,size,unused):
        p=self.placement;r=self.r
        if (self.code_address<=pc<self.code_address+r['code_size'] or r['run_veneer']<=pc<r['run_veneer']+8 or
                r['dispatch_veneer']<=pc<r['dispatch_veneer']+8 or
                p['left_code']<=pc<p['left_code']+p['left_size'] or
                p['right_code']<=pc<p['right_code']+p['right_size']):return
        if self.worker is not None:
            if pc==0xb82c80:self.gates.append(v.word(u,B.component.GATE))
            self.worker.code(u,pc,size,unused);return
        if pc==0x564b38 and self.enqueue_fail==self.attempts:
            self.ret(-1);return
        if pc==0x565300:
            self.free_calls+=1;self.ret();return
        super().code(u,pc,size,unused)

    def core(self,name,*args):
        return self.call(self.placement['core_addresses'][name],self.placement['state'],*args)

    def open(self):assert self.core('lh_cp_open',0x1234,0x5678,17)==1

    def request(self,id=1):
        self.u.mem_write(lease.INPUT,lease.request(id=id))
        self.u.mem_write(lease.OUTPUT,b'\xa5'*40)
        assert self.core('lh_cp_request',lease.INPUT,32,lease.OUTPUT)==2
        assert self.u.mem_read(lease.OUTPUT+32,8)==b'\xa5'*8
        return self.u.mem_read(lease.OUTPUT+15,1)[0]

    def produce(self,art):
        for address in (v.STATE,v.DESC,v.RES):v.put(self.u,address,0)
        self.u.mem_write(v.PENDING,b'\0')
        self.apply(art);self.apply(art)
        return [struct.unpack_from('<I',m)[0] for m in self.queued]

    def tokens(self):
        return [struct.unpack_from('<I',m,4)[0] for m in self.queued if struct.unpack_from('<I',m)[0] in (1,3)]

    def bits(self):return v.word(self.u,B.component.GATE)&0x1fffffff

    def work(self,cp,payload,modes=None):
        # The worker fixture delegates its hooks into this same native machine;
        # leases originate in actual producer instructions and are never copied.
        w=runtime.Integrated(cp,payload,self.r,self.queued,modes or ['success']*len(self.queued))
        w.u=self.u;self.worker=w
        self.u.mem_map(0x2600000,0x100000)
        w.loop()
        return w


def main():
    cp,payload,r=build.make()
    cold=[];flows=[];failures=[];faults=[];edges=[]
    parent_cp,_=B.parent.make()
    for mode in (False,True):
        u,check=coldcheck.cold(cp,payload,r,mode)
        n=Owner(cp,payload,r,cold_machine=u);n.open()
        assert n.produce(True)==[1,3,2]
        assert len(set(n.tokens()))==2 and n.bits().bit_count()==2
        assert n.request()==1
        w=n.work(cp,payload)
        assert w.results==[0,0,0] and w.callback_results==[0]
        assert [x&0x1fffffff for x in n.gates]==[2,0,0]
        assert n.request()==0
        cold.append({'boot':check,'cold_to_enqueue_to_worker':True,'write_busy_before_drain':True,
                     'reader_bits_after_each_message':[x&0x1fffffff for x in n.gates],
                     'write_allowed_after_drain':True})
    for mask in ownership.GROUPS:
        for mode in (0,1):
            for art in (False,True):
                n=Owner(cp,payload,r,mask=mask,mode=mode);n.open()
                expected=[1,3,2] if art else [1,2]
                assert n.produce(art)==expected
                baseline=queue.Producer(parent_cp,0,mask,mode)
                for address in (v.STATE,v.DESC,v.RES):v.put(baseline.u,address,0)
                baseline.u.mem_write(v.PENDING,b'\0');baseline.apply(art);baseline.apply(art)
                for actual,original in zip(n.queued,baseline.queued,strict=True):
                    normalized=bytearray(actual)
                    if struct.unpack_from('<I',actual)[0] in (1,3):normalized[4:8]=bytes(4)
                    assert bytes(normalized)==original
                tokens=n.tokens();assert all(tokens) and len(set(tokens))==len(tokens)
                assert n.bits().bit_count()==len(tokens)
                assert n.request()==1
                w=n.work(cp,payload)
                assert w.results==[0]*len(expected) and w.callback_results==[0]
                assert not n.bits() and n.request()==0
                for token in tokens:assert n.core('lh_cp_reader_end',token)==0
                flows.append({'mask':mask,'mode':mode,'art':art,'tokens':tokens,'busy_then_granted':True})
    for art in (False,True):
        types=[1,3,2] if art else [1,2]
        for index in range(1,len(types)+1):
            for kind in ('allocation','enqueue'):
                n=Owner(cp,payload,r,fail_at=index if kind=='allocation' else 0,
                        enqueue_fail=index if kind=='enqueue' else 0);n.open()
                assert n.produce(art)==types[:index-1]
                count=sum(t in (1,3) for t in types[:index-1])
                assert n.bits().bit_count()==count
                assert n.free_calls==(kind=='enqueue')
                assert n.u.mem_read(v.PENDING,1)==b'\0'
                if count:
                    assert n.request()==1
                    w=n.work(cp,payload)
                    assert w.results==[0]*(index-1) and not w.callback_results
                assert not n.bits() and n.request()==0
                failures.append({'art':art,'failure':kind,'index':index,'queued_readers_retained':count,
                                 'unqueued_reader_released':True,'permission_after_drain':True})
        n=Owner(cp,payload,r);n.open();assert n.request()==0
        assert n.produce(art)==[] and n.attempts==0 and not n.bits()
        failures.append({'art':art,'closed_gate_prevents_allocation':True})
        for index in range(len(types)):
            for mode,code in [('dma_error',-6),('timeout',-7),('missing_completion',-20)]:
                n=Owner(cp,payload,r);n.open();assert n.produce(art)==types
                tokens=n.tokens();assert n.request()==1
                modes=['success']*len(types);modes[index]=mode
                w=n.work(cp,payload,modes)
                assert w.results==[0]*index+[code]+[-20]*(len(types)-index-1)
                assert w.callback_results==[code if index==len(types)-1 else -20]
                if types[index] in (1,3):
                    failed=tokens[index]
                    assert n.bits()==1<<(failed&31)
                    assert n.core('lh_cp_reader_end',failed)==0
                else:assert n.bits()==0
                assert n.request()==2
                before=n.bits();callbacks=list(w.callback_results)
                for value in (0,1,0):n.call(runtime.native.ISR,value)
                assert n.bits()==before and w.callback_results==callbacks
                faults.append({'art':art,'index':index,'mode':mode,'retained_failed_reader_bits':before,
                               'queued_unstarted_readers_released':True,'late_completion_keeps_fault':True})
    for occupied in (28,29):
        n=Owner(cp,payload,r);n.open()
        existing=[n.core('lh_cp_reader_begin') for _ in range(occupied)]
        assert all(existing)
        assert n.produce(True)==([1] if occupied==28 else [])
        assert n.bits().bit_count()==29 and n.attempts==(1 if occupied==28 else 0)
        assert n.request()==1
        if n.queued:
            w=n.work(cp,payload);assert w.results==[0] and not w.callback_results
        assert n.bits().bit_count()==occupied and n.request()==1
        for token in existing:assert n.core('lh_cp_reader_end',token)==1
        assert n.request()==0
        edges.append({'occupied':occupied,'capacity_failure_preserves_other_readers':True,
                      'permission_only_after_all_readers_end':True})
    n=Owner(cp,payload,r);n.open();assert n.produce(False)==[1,2]
    w=n.work(cp,payload);assert w.results==[0,0] and not n.bits()
    submissions=w.timeline.count('submit_dma')
    n.u.mem_write(lease.INPUT,n.queued[0])
    assert n.call(r['addresses']['lut_dma_dispatch'],lease.INPUT)==(-20&0xffffffff)
    assert w.timeline.count('submit_dma')==submissions
    assert v.word(n.u,B.STATE)==3 and n.request()==2
    edges.append({'replayed_completed_message_rejected':True,'no_duplicate_dma':True,'write_permission_denied':True})
    report={'status':'NATIVE_ENQUEUE_AND_COMPLETION_LEASES_VERIFIED_NOT_FLASHABLE','camera_io':False,
            'in_memory_cp_sha256':r['in_memory_cp_sha256'],'recipe_sha256':B.b.sha((build.OUT/'recipe.json').read_bytes()),
            'cold_cases':cold,'normal_flows':flows,'enqueue_failures':failures,'dma_faults':faults,'edge_cases':edges,
            'source_sha256':{name:B.b.sha((B.HERE/name).read_bytes()) for name in
                             ('verify_lut_reader_placement.py','verify_lut_dma_placement.py','verify_lut_dma_worker.py',
                              'verify_queue_allocation_guard.py','verify_lut_ownership.py','verify_resource_release.py',
                              'verify_lut_handoff_cp.py')},
            'limitations':['Leases start before queue allocation/copy but after the native producer captured its source descriptor; upstream snapshot protection is still missing.',
                           'Tokens occupy word +4 only in native type-1/type-3 messages; other message kinds are unchanged.',
                           'OS allocation/enqueue/free, events and DMA timing are explicit fixtures; hardware quiescence is not proven.',
                           'Application callbacks are still deferred to worker context; complete callback compatibility and WBI are pending.',
                           'Real private IPC/session and AP upload owner are not connected, and no complete flashable image is exported.']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cold':len(cold),'flows':len(flows),'enqueue_failures':len(failures),'dma_faults':len(faults),'edge_cases':len(edges)}))


if __name__=='__main__':main()
