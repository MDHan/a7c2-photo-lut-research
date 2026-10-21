"""Native cached-context callsites revalidate before source addresses are used."""
import json
import struct
import sys
from unicorn import UC_MEM_READ
from unicorn import arm_const as ar
import build_lut_native_reader as build
import verify_lut_reader_placement as readers
import verify_lut_photo_reader as photo

B=build.base
v=readers.v
own=readers.ownership
SITES=(0x4c2eae,0xb2b4d4,0xb2b596,0xb2ba0e)
INPUT,OUTPUT=v.RAM+0xe000,v.RAM+0xe100
TRAMP=v.STOP+0x500
PARAMETERS=v.RAM+0xa000


class Native(readers.Owner):
    def __init__(self,cp,payload,r,site=SITES[0],art=False,probe=None,mutate_context=False,**kw):
        self.site=site;self.probe=probe;self.resume=None;self.probes=[]
        self.native_entries=[];self.global_reads=[];self.mutate_context=mutate_context
        self.rebuilding=False;self.builder_reads=[];self.builder_copies=[]
        super().__init__(cp,payload,r,**kw)
        v.put(self.u,own.CTX+0x2c,0x7c if art else 0)
        self.u.mem_write(v.G+0x68,bytes(self.u.mem_read(own.CTX+0x18,96)))
        self.original=bytes(self.u.mem_read(own.CTX,120))
        for a in (v.STATE,v.DESC,v.RES):v.put(self.u,a,0)
        self.u.mem_write(v.PENDING,b'\0')

    def memory(self,u,access,address,size,value,unused):
        if access==UC_MEM_READ and v.G+0x68<=address<v.G+0xc8:
            if self.rebuilding:self.builder_reads.append(address)
            else:
                assert self.bits()&1  # In these cases the parent always owns slot 0.
                self.global_reads.append(address)
        super().memory(u,access,address,size,value,unused)

    def code(self,u,pc,size,unused):
        if self.rebuilding:
            if (0xb2c406<=pc<0xb2c5fc or 0xb2ddb4<=pc<0xb2ddbe or
                    0xb31aac<=pc<0xb31ac4 or 0x4e8a5c<=pc<0x4e8b22):return
            if pc==0x61e60c:
                a=[u.reg_read(v.reg(i)) for i in range(3)]
                assert a==[PARAMETERS+0x13d0,v.G+0x68,96]
                self.builder_copies.append(a)
                u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])));self.ret(a[0]);return
            if pc==0xb4361c:self.ret();return
        if pc==TRAMP:
            assert self.resume is not None
            assert u.reg_read(v.reg(0))==2 and u.mem_read(OUTPUT+15,1)==b'\1'
            context,resume=self.resume;self.resume=None
            self.probes.append({'pc':hex(resume),'bits':self.bits(),'writer_busy':True})
            u.context_restore(context);u.reg_write(ar.UC_ARM_REG_PC,resume|1);return
        if self.probe==pc:
            self.probe=None
            assert self.bits()&1
            self.resume=(u.context_save(),pc)
            u.mem_write(INPUT,readers.lease.request())
            for i,x in enumerate((self.placement['state'],INPUT,32,OUTPUT)):u.reg_write(v.reg(i),x)
            u.reg_write(ar.UC_ARM_REG_LR,TRAMP|1)
            u.reg_write(ar.UC_ARM_REG_PC,self.placement['core_addresses']['lh_cp_request']|1)
            return
        if pc in SITES:return
        if pc==0x4e876c:
            owner=u.reg_read(v.reg(0));context=u.reg_read(v.reg(1))
            self.native_entries.append({'owner':owner,'context':bytes(u.mem_read(context,120)).hex(),
                                        'bits':self.bits(),'stack_copy':context!=own.CTX})
            if self.mutate_context:
                self.mutate_context=False
                # Change the caller's cached descriptor after validation; the
                # native function must continue using the already copied one.
                u.mem_write(own.CTX+0x18,b'\xa5'*96)
        super().code(u,pc,size,unused)

    def invoke(self,owner=own.OWNER,context=own.CTX):
        u=self.u
        for reg,val in self.saved.items():u.reg_write(reg,val)
        u.reg_write(v.reg(0),owner);u.reg_write(v.reg(1),context)
        u.reg_write(ar.UC_ARM_REG_SP,v.SP)
        u.emu_start(self.site|1,self.site+4,count=100000)
        assert u.reg_read(ar.UC_ARM_REG_PC)==self.site+4
        assert u.reg_read(ar.UC_ARM_REG_SP)==v.SP
        assert all(u.reg_read(reg)==val for reg,val in self.saved.items())

    def rebuild(self):
        # Execute the real native cache builder. Its input pointer graph,
        # ordinary memcpy and trace sink are explicit fixtures here.
        for address,value in [(0x173efe8,v.G),(0x173eff8,v.RAM+0xc200),
                              (0x173f018,v.RAM+0xc000),
                              (v.G+0xaf8,10),(v.G+0xafc,0),(v.G+0xb04,1),
                              (v.G+0xb00,0),(v.G+0xb08,0)]:v.put(self.u,address,value)
        self.rebuilding=True
        try:self.call(0xb2c406,PARAMETERS)
        finally:self.rebuilding=False
        assert self.builder_copies==[[PARAMETERS+0x13d0,v.G+0x68,96]]
        assert self.u.mem_read(PARAMETERS+0x13d0,96)==self.u.mem_read(v.G+0x68,96)
        assert v.word(self.u,PARAMETERS+0x13c0)==10


def main():
    cp,payload,r=build.make();flows=[];stale=[];blocked=[];injections=[];failures=[]
    for site in SITES:
        for mask in own.GROUPS:
            for mode in (0,1):
                for art in (False,True):
                    n=Native(cp,payload,r,site=site,mask=mask,mode=mode,art=art);n.open()
                    n.invoke();assert not n.queued and not n.bits() and v.word(n.u,v.STATE)==1
                    n.invoke()
                    kinds=[struct.unpack_from('<I',m)[0] for m in n.queued]
                    assert kinds==([1,3,2] if art else [1,2])
                    assert all(x['context']==n.original.hex() and x['bits']&1 and x['stack_copy'] for x in n.native_entries)
                    assert n.u.mem_read(own.CTX,120)==n.original
                    assert n.bits().bit_count()==(2 if art else 1) and not n.bits()&1
                    assert n.request()==1
                    w=n.work(cp,payload)
                    assert w.results==[0]*len(kinds) and w.callback_results==[0]
                    assert not n.bits() and n.request()==0
                    flows.append({'site':hex(site),'mask':mask,'mode':mode,'art':art,'types':kinds})
    for index in range(24):
        n=Native(cp,payload,r,art=True);n.open()
        v.put(n.u,v.G+0x68+4*index,v.word(n.u,v.G+0x68+4*index)^1)
        n.invoke()
        assert not n.native_entries and not n.bits() and not n.queued and n.attempts==0
        assert n.request()==0
        stale.append({'word':index,'native_not_called':True,'parent_released':True})
    for site in SITES:
        for reason in ('closed','invalid','fault','capacity'):
            n=Native(cp,payload,r,site=site);n.open()
            if reason=='closed':assert n.request()==0
            elif reason=='invalid':v.put(n.u,B.component.GATE,0x40000000)
            elif reason=='fault':v.put(n.u,B.component.GATE,0x20000000)
            else:assert all(n.core('lh_cp_reader_begin') for _ in range(29))
            bits=n.bits();n.invoke()
            assert n.bits()==bits and not n.native_entries and not n.global_reads and not n.queued
            blocked.append({'site':hex(site),'reason':reason})
    for art in (False,True):
        kinds=[1,3,2] if art else [1,2]
        for index in range(1,len(kinds)+1):
            n=Native(cp,payload,r,art=art,fail_at=index);n.open();n.invoke();n.invoke()
            assert [struct.unpack_from('<I',m)[0] for m in n.queued]==kinds[:index-1]
            count=sum(x in (1,3) for x in kinds[:index-1])
            assert n.bits().bit_count()==count and not n.bits()&1
            if count:
                assert n.request()==1
                assert n.work(cp,payload).results==[0]*(index-1)
            assert n.request()==0
            failures.append({'art':art,'allocation_failure':index,'retained_children':count})
    for at,expected in [(0xb79a6a,[]),(0xb79b3a,[1])]:
        n=Native(cp,payload,r,art=True,probe=at);n.open();n.invoke();n.invoke()
        assert len(n.probes)==1 and [struct.unpack_from('<I',m)[0] for m in n.queued]==expected
        assert n.bits().bit_count()==len(expected) and not n.bits()&1
        if expected:
            assert n.request()==1
            assert n.work(cp,payload).results==[0]
        assert n.request()==0
        injections.append({'at':hex(at),'queued':expected,'writer_busy_until_all_readers_end':True})
    immutable=[]
    for art in (False,True):
        n=Native(cp,payload,r,art=art);n.open();n.invoke()
        n.mutate_context=True;n.invoke()
        assert n.native_entries[-1]['context']==n.original.hex()
        assert [struct.unpack_from('<I',m)[0] for m in n.queued]==([1,3,2] if art else [1,2])
        assert n.u.mem_read(own.CTX+0x18,96)==b'\xa5'*96
        assert n.request()==1
        assert n.work(cp,payload).results==[0]*len(n.queued)
        assert n.request()==0
        immutable.append({'art':art,'caller_changed_after_validation':True,'uses_private_copy':True})
    bypass=[]
    for site in SITES:
        for reason in ('owner_zero','configuration_zero','builtin_ready'):
            n=Native(cp,payload,r,site=site);n.open();assert n.request()==0
            if reason=='configuration_zero':v.put(n.u,own.CTX,0)
            if reason=='builtin_ready':
                v.put(n.u,own.CTX+8,9);v.put(n.u,v.STATE,2);v.put(n.u,v.DESC,9)
            n.invoke(owner=0 if reason=='owner_zero' else own.OWNER,
                     context=0 if reason=='owner_zero' else own.CTX)
            assert not n.bits() and not n.global_reads and not n.queued
            assert len(n.native_entries)==int(reason=='builtin_ready')
            bypass.append({'site':hex(site),'reason':reason})
    rebuilt=[]
    for art in (False,True):
        n=Native(cp,payload,r,art=art);n.open()
        v.put(n.u,v.G+0xc0,v.word(n.u,v.G+0xc0)+1)
        n.invoke();assert not n.native_entries and not n.queued and not n.bits()
        n.rebuild()
        assert n.u.mem_read(own.CTX,120)==n.original
        n.invoke(context=PARAMETERS+0x13b8);n.invoke(context=PARAMETERS+0x13b8)
        kinds=[struct.unpack_from('<I',m)[0] for m in n.queued]
        assert kinds==([1,3,2] if art else [1,2])
        assert n.request()==1
        assert n.work(cp,payload).results==[0]*len(kinds)
        assert n.request()==0
        rebuilt.append({'art':art,'stale_rejected':True,'native_builder_copy_requests':n.builder_copies,
                        'rebuilt_context_submitted_types':kinds,'write_after_drain':True})
    sys.path.insert(0,str(B.HERE.parents[1]))
    import inspect_current_firmware as inventory
    frozen=(B.HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    direct={'status':'DIRECT_CALL_INVENTORY_ONLY','camera_io':False,'cp_sha256':B.b.sha(frozen),
            'calls':inventory.direct_thumb_calls(frozen,[0x4e876c,0xb2c406,0x54e15c,0x54e398,0xb799de,0xb79ab4]),
            'scanner_sha256':B.b.sha((B.HERE.parents[1]/'inspect_current_firmware.py').read_bytes()),
            'limitations':['Direct Thumb BL only; not an indirect-call exclusion, complete CFG or runtime mode attribution.']}
    assert direct['calls']['0x4e876c']==[hex(x) for x in SITES]
    (build.OUT/'direct-call-inventory.json').write_text(json.dumps(direct,indent=2)+'\n')
    report={'status':'NATIVE_CACHED_CONTEXT_GUARDS_VERIFIED_NOT_FLASHABLE','camera_io':False,
            'in_memory_cp_sha256':r['in_memory_cp_sha256'],'recipe_sha256':B.b.sha((build.OUT/'recipe.json').read_bytes()),
            'normal_flows':flows,'stale_descriptor_words':stale,'blocked':blocked,'allocation_failures':failures,
            'writer_injections':injections,'immutable_context':immutable,'bypass':bypass,
            'native_cache_rebuild':rebuilt,
            'direct_call_inventory_sha256':B.b.sha((build.OUT/'direct-call-inventory.json').read_bytes()),
            'source_sha256':{name:B.b.sha((B.HERE/name).read_bytes()) for name in
                             ('verify_lut_native_reader.py','verify_lut_reader_placement.py','verify_lut_dma_worker.py',
                              'verify_queue_allocation_guard.py','verify_lut_ownership.py','verify_resource_release.py',
                              'verify_lut_handoff_cp.py','verify_queue_completion.py')},
            'limitations':['Only four identified native cached-context callsites are patched; indirect calls and lower-level external-buffer APIs are not proven covered.',
                           'The test supplies caller context and executes the actual call instruction and callee; it does not execute the complete caller or UI scheduler.',
                           'Native cache rebuild executes with pointer-graph/memcpy fixtures; its real event scheduling after rejection is still unproven.',
                           'AP upload owner and actual IPC/session are not connected; OS, MMIO and DMA remain fixtures.',
                           'No complete firmware export, camera operation, hardware recovery, WBI or production installation.']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'flows':len(flows),'stale':len(stale),'blocked':len(blocked),
                      'failures':len(failures),'writer_injections':len(injections),'immutable':len(immutable),'bypass':len(bypass),
                      'native_rebuild':len(rebuilt)}))
    photo.main(build,'photo-regression.json')


if __name__=='__main__':main()
