"""Actual photo callsite, pre-snapshot lease, and retained native queue readers.

OS, register banks, driver profile configuration, physical DMA and VFX remain
explicit fixture boundaries. No camera, full-image export, or flash readiness.
"""
import itertools
import json
import struct
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_MEM_READ,UC_PROT_READ,UC_PROT_EXEC
from unicorn import arm_const as ar
import build_lut_photo_reader as build
import verify_reusable_entry as photo
import verify_lut_reader_placement as readers

B=build.base
v=photo.v
lease=readers.lease
own=readers.ownership
INPUT,OUTPUT=v.RAM+0xe000,v.RAM+0xe100


class Photo(photo.Photo):
    def __init__(self,cp,payload,r,*args,probe=None,native_load=False,fail_at=0,cold_machine=None,**kwargs):
        self.code_address=r.get('code_address',B.CODE);self.r=r;self.snapshot_reads=[];self.writer_probe=probe;self.probed=[]
        self.native_load=native_load;self.loading_return=None;self.owner=None;self.worker=None
        self.placement=json.loads((B.parent.parent.OUT/'recipe.json').read_text())
        previous=photo.old.storage_test.cold_init
        def initialized(u,modified):
            assert modified
            for cell in photo.old.storage.CELLS:v.put(u,cell,0x80)
            u.mem_write(self.placement['state'],bytes(148));v.put(u,B.STATE,0)
        try:
            photo.old.storage_test.cold_init=initialized
            m=json.loads((photo.build.OUT/'recipe.json').read_text())
            super().__init__(cp,m,*args,**kwargs)
        finally:photo.old.storage_test.cold_init=previous
        if cold_machine is not None:
            fixture=self.u;self.u=cold_machine
            # Copy only the explicit native OS/registry/register fixtures;
            # retain boot's private state and its actual copied executable.
            for address,count in [(v.RAM,0x10000),(0xe9515c,28),(0xe9d550,28),(0xe9d588,56)]:
                self.u.mem_write(address,bytes(fixture.mem_read(address,count)))
            self.setup()
            for channel in range(4):self.configure_gate(channel,15)
            assert self.u.mem_read(self.code_address,len(payload))==payload
            assert self.u.mem_read(self.placement['state'],148)==bytes(148)
            assert v.word(self.u,B.STATE)==0
            assert [v.word(self.u,c) for c in photo.old.storage.CELLS]==[0x80,0x80]
            self.u.hook_add(UC_HOOK_CODE,self.code)
            self.u.hook_add(UC_HOOK_MEM_WRITE,self.memory)
            self.u.hook_add(UC_HOOK_MEM_READ,self.memory)
        else:self.u.mem_write(self.code_address,payload)
        self.u.mem_protect(self.code_address,4096,UC_PROT_READ|UC_PROT_EXEC)
        if native_load:
            self.owner=readers.Owner(cp,payload,r,fail_at=fail_at)
            for address,count in [(v.RAM+0x4000,0x2000),(own.REGISTRY,32),(own.SHADOW,16),
                                  (0xceedb0,32),(0xe9515c,28),(0xe9d550,28),(0xe9d588,56)]:
                self.u.mem_write(address,bytes(self.owner.u.mem_read(address,count)))
            self.owner.u=self.u
            # Keep both source addresses inside the explicit conversion span.
            # The older photo-only fixture never executed this conversion.
            v.put(self.u,v.G+0x70,0x7008000)

    def bits(self):return v.word(self.u,B.component.GATE)&0x1fffffff

    def core(self,name,*args):
        return self.call(self.placement['core_addresses'][name],self.placement['state'],*args)

    def open(self):assert self.core('lh_cp_open',0x1234,0x5678,17)==1

    def request(self):
        self.u.mem_write(INPUT,lease.request())
        assert self.core('lh_cp_request',INPUT,32,OUTPUT)==2
        return self.u.mem_read(OUTPUT+15,1)[0]

    def memory(self,u,access,address,size,value,unused):
        if access==UC_MEM_READ and ((v.G+0x68<=address<v.G+0xc8) or address==v.G+0x684):
            pc=u.reg_read(ar.UC_ARM_REG_PC)
            # These photo cases begin without other readers: the parent owns
            # slot zero, while any actual queued children occupy later slots.
            assert self.bits()&1,('unprotected parent snapshot read',hex(pc),hex(address))
            self.snapshot_reads.append((pc,address,self.bits()))
        super().memory(u,access,address,size,value,unused)

    def code(self,u,pc,size,unused):
        if pc==photo.old.TRAMP:
            super().code(u,pc,size,unused);return
        if self.writer_probe==pc:
            self.writer_probe=None
            assert self.bits()
            u.mem_write(INPUT,lease.request())
            def after():
                status=u.mem_read(OUTPUT+15,1)[0]
                assert status==1
                self.probed.append({'pc':hex(pc),'status':status,'reader_bits':self.bits()})
                u.reg_write(ar.UC_ARM_REG_PC,pc|1)
                self.code(u,pc,size,unused)
            self.inject([(self.placement['core_addresses']['lh_cp_request'],
                          (self.placement['state'],INPUT,32,OUTPUT))],after)
            return
        p=self.placement;r=self.r
        if (self.code_address<=pc<self.code_address+r['code_size'] or r['dispatch_veneer']<=pc<r['dispatch_veneer']+8 or
                r['run_veneer']<=pc<r['run_veneer']+8 or
                p['left_code']<=pc<p['left_code']+p['left_size'] or
                p['right_code']<=pc<p['right_code']+p['right_size']):return
        if self.worker is not None:
            self.worker.code(u,pc,size,unused);return
        if self.native_load:
            if pc==self.loading_return:self.loading_return=None
            if pc in (0xbb2bca,0x54e15c,0x54e398):
                self.loading_return=u.reg_read(ar.UC_ARM_REG_LR)&~1
                if pc!=0xbb2bca:self.loads.append(pc)
            if self.loading_return is not None:
                self.owner.code(u,pc,size,unused);return
            if pc==0x5f4144:
                # No worker scheduled during this capture: retain the actual
                # queued messages and exercise the photo timeout return.
                self.delays+=1;self.ret();return
        super().code(u,pc,size,unused)

    def drain(self,cp,payload,modes=None):
        w=readers.runtime.Integrated(cp,payload,self.r,self.owner.queued,
                                     modes or ['success']*len(self.owner.queued))
        w.u=self.u;self.worker=w
        self.u.mem_map(0x2600000,0x100000)
        w.loop()
        return w


def main(component=build,report_name='verification.json'):
    cp,payload,r=component.make()
    cold=[];normal=[];errors=[];blocked=[];probes=[];retained=[]
    for mode in (False,True):
        u,report=readers.coldcheck.cold(cp,payload,r,mode)
        n=Photo(cp,payload,r,cold_machine=u);n.open()
        assert n.run()==(0x48c790,0) and n.snapshot_reads and not n.bits()
        n.finish_vfx();assert n.request()==0
        cold.append({'boot':report,'photo_uses_cold_copied_code_and_state':True})
    for context,kind in itertools.product((0,1),range(3,10)):
        count,_=photo.old.mapping(kind)
        for mask in range(1,1<<count):
            n=Photo(cp,payload,r,context,kind,mask);n.open()
            for epoch in (1,2):
                assert n.run()==(0x48c790,0)
                n.check_descriptors(epoch*0x1000|2)
                assert n.snapshot_reads and not n.bits()
                n.finish_vfx();assert v.word(n.u,n.cell)==epoch*0x1000
                n.prepare_next()
            assert n.request()==0
            normal.append({'context':context,'kind':kind,'mask':mask,'captures':2})
    for mode,error in [('async_load',0),('early_callbacks',0),('acquire_failure',2),
                       ('load_submit_failure',2),('load_callback_failure',2),('timeout',6),
                       ('delay_error',7),('settings_change',3),('submit_failure',10)]:
        n=Photo(cp,payload,r,mode=mode);n.open()
        result=n.run()
        assert result==((0x48c778,0xc17e0000|error) if error else (0x48c790,0)),(mode,result)
        assert not n.bits() and n.request()==0
        errors.append({'mode':mode,'error':error,'parent_released':True})
    for state in ('closed','invalid','fault','capacity'):
        n=Photo(cp,payload,r);n.open()
        if state=='closed':assert n.request()==0
        elif state=='invalid':v.put(n.u,B.component.GATE,0x40000000)
        elif state=='fault':v.put(n.u,B.component.GATE,0x20000000)
        else:assert all(n.core('lh_cp_reader_begin') for _ in range(29))
        before=n.bits()
        assert n.run()==(0x48c778,0xc17e000b)
        assert not n.snapshot_reads and not n.loads and not n.submissions and n.bits()==before
        assert v.word(n.u,n.cell)==0x80
        blocked.append({'state':state,'error':11,'no_descriptor_read_or_native_submit':True})
    bypass=[]
    for reason in ('non_user','alternate_path','no_raw'):
        n=Photo(cp,payload,r,mode='non_user' if reason=='non_user' else 'ready',mask=0 if reason=='no_raw' else 15)
        n.open();assert n.request()==0
        if reason=='alternate_path':v.put(n.u,v.G+0xafc,1)
        assert n.run()==(0x48c790,0)
        assert not n.snapshot_reads and not n.bits() and not n.loads
        assert v.word(n.u,n.cell)==0x80
        n.descriptor_check(False)
        bypass.append(reason)
    for at,mode in [(0xc2f490,'ready'),(0x4e8a5c,'ready'),(0x54e398,'async_load'),(0x5f4144,'async_load')]:
        n=Photo(cp,payload,r,mode=mode,probe=at);n.open()
        assert n.run()==(0x48c790,0)
        assert len(n.probed)==1 and not n.bits() and n.request()==0
        probes.extend(n.probed)
    for art in (False,True):
        types=[1,3,2] if art else [1,2]
        for fail in range(len(types)+1):
            n=Photo(cp,payload,r,mode='async_load',native_load=True,fail_at=fail);n.open()
            if not art:v.put(n.u,v.G+0x7c,0)
            result=n.run()
            assert result==(0x48c778,0xc17e0002 if fail else 0xc17e0006),(art,fail,result)
            queued=n.owner.queued
            expected=types[:fail-1] if fail else types
            assert [struct.unpack_from('<I',m)[0] for m in queued]==expected
            data=[m for m in queued if struct.unpack_from('<I',m)[0] in (1,3)]
            assert n.bits().bit_count()==len(data)
            assert all(struct.unpack_from('<I',m,4)[0] for m in data)
            if data:
                assert n.request()==1
                w=n.drain(cp,payload);assert w.results==[0]*len(queued)
                assert w.callback_results==([0] if not fail else [])
            assert not n.bits() and n.request()==0
            retained.append({'art':art,'allocation_failure_at':fail,'photo_error':hex(result[1]),
                             'queued_types':expected,'retained_child_readers':len(data),
                             'write_permission_after_native_worker_drain':True})
    queue_probes=[]
    for at,expected in [(0xb79a6a,[]),(0xb79b3a,[1])]:
        n=Photo(cp,payload,r,mode='async_load',native_load=True,probe=at);n.open()
        assert n.run()==(0x48c778,0xc17e0002)
        assert len(n.probed)==1
        assert [struct.unpack_from('<I',m)[0] for m in n.owner.queued]==expected
        assert n.bits().bit_count()==len(expected)
        assert not n.bits()&1  # The photo's parent slot has been released.
        if expected:
            assert n.request()==1
            assert n.drain(cp,payload).results==[0]
        assert not n.bits() and n.request()==0
        queue_probes.append({'pc':hex(at),'writer_busy_during_source_capture':True,
                             'accepted_types':expected,'later_enqueue_denied':True,
                             'permission_only_after_parent_and_children_end':True})
    # The variadic dispatch still accepts actual one-argument queue/worker
    # calls. Exercise fault retention on the final composed image as well.
    faults=[]
    for art in (False,True):
        n=readers.Owner(cp,payload,r);n.open();n.produce(art)
        assert n.request()==1
        w=n.work(cp,payload,['dma_error']+['success']*(len(n.queued)-1))
        assert w.results==[-6]+[-20]*(len(n.queued)-1)
        assert n.bits().bit_count()==1 and n.request()==2
        faults.append({'art':art,'results':w.results,'failed_child_reader_retained':True})
    again,code,repeat=component.make()
    assert again==cp and code==payload and repeat==r
    report={'status':'PHOTO_SNAPSHOT_AND_QUEUED_READERS_VERIFIED_NOT_FLASHABLE','camera_io':False,
            'in_memory_cp_sha256':r['in_memory_cp_sha256'],'recipe_sha256':B.b.sha((component.OUT/'recipe.json').read_bytes()),
            'cold_cases':cold,'normal_flows':normal,'errors':errors,'blocked':blocked,'bypass':bypass,
            'writer_injections':probes,'native_queued_readers':retained,'dma_faults':faults,
            'native_queue_writer_injections':queue_probes,
            'repeat_build_identical':True,
            'source_sha256':{name:B.b.sha((B.HERE/name).read_bytes()) for name in
                             ('verify_lut_photo_reader.py','verify_reusable_entry.py','verify_tracked_entry.py',
                              'verify_lut_reader_placement.py','verify_lut_dma_placement.py','verify_lut_dma_worker.py',
                              'verify_queue_allocation_guard.py','verify_lut_ownership.py','verify_resource_release.py',
                              'verify_lut_handoff_cp.py','verify_vfx_completion.py','verify_queue_completion.py')},
            'limitations':['Only the custom photo entry has pre-snapshot protection; other native producers still need earlier protection.',
                           'AP upload ownership and actual IPC/session transport are not connected.',
                           'Writer timing, OS, MMIO, physical DMA, VFX submission and profile configuration are explicit fixtures.',
                           'Fault quarantine does not prove hardware DMA cancellation or recovery; WBI and production installer remain unfinished.',
                           'No complete flashable image or real JPEG output was generated.']}
    (component.OUT/report_name).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cold':len(cold),'flows':len(normal),'errors':len(errors),
                      'blocked':len(blocked),'bypass':len(bypass),'injections':len(probes),
                      'queued':len(retained),'queue_injections':len(queue_probes),'dma_faults':len(faults)}))


if __name__=='__main__':main()
