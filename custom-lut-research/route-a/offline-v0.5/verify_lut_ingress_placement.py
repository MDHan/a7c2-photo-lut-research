"""Native cold copy, exact parameter restore and placed CP receive loop."""
import json
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ,UC_PROT_READ,UC_PROT_EXEC
from unicorn import arm_const as ar
import build_lut_ingress_placement as build
import verify_lut_dma_placement as oldboot
import verify_lut_cp_ingress as ipc
import verify_lut_photo_reader as photos
import verify_lut_native_reader as native

b=build.b
boot=oldboot.boot
v=boot.v


def cold(cp,payload,r,mode):
    parent,parent_payload,pr=build.parent.make()
    old,old_tables,_=boot.tables(parent,mode)
    old_ranges=oldboot.allocator(old)
    u,tables,info=boot.tables(cp,mode)
    l1=int(info['l1'],16)
    pte=lambda va:oldboot.placed.pte_address(u,va)
    code_pte,scratch_pte,ro_pte=map(pte,(build.CODE,build.SCRATCH,0x10c6000))
    assert v.word(u,code_pte)==build.CODE|0x433
    assert v.word(u,scratch_pte)==build.SCRATCH|0x41f
    expected=bytearray(old_tables)
    struct.pack_into('<I',expected,scratch_pte-l1,build.SCRATCH|0x41f)
    assert bytes(expected)==tables
    first=json.loads((build.publication.base.parent.parent.OUT/'recipe.json').read_text())
    stages=[(first['storage_init'],first['storage_size']),(r['copy_init'],r['copy_init_size'])]
    arm=Cs(CS_ARCH_ARM,CS_MODE_ARM);thumb=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    instructions={i.address:i for a,n in stages for i in arm.disasm(cp[a-b.CP_DELTA:a-b.CP_DELTA+n],a)}
    offset=r['restore_code_start']-build.CODE
    instructions.update({i.address:i for i in thumb.disasm(payload[offset:offset+r['restore_code_size']],r['restore_code_start'])})
    native=parent[build.PARAMETERS-b.CP_DELTA:build.PARAMETERS-b.CP_DELTA+build.PARAMETER_BYTES]
    code_cleans=[];parameter_cleans=[];table_writes=[];events=[];decoded=[];restored=[]
    saved={};read_end=build.PARAMETERS+r['packed_bytes']
    u.mem_write(boot.START,b'\xa5'*(build.CODE+4096-boot.START))
    v.put(u,boot.START+0x14,boot.FLAG);v.put(u,boot.FLAG,0)
    prefix=bytes(u.mem_read(boot.START,0x418))
    def step(u,pc,size,unused):
        if pc==(r['restore_address']&~1):
            saved.update({reg:u.reg_read(reg) for reg in [v.reg(i) for i in range(4,12)]+[ar.UC_ARM_REG_SP]})
            assert bytes(u.mem_read(build.CODE,len(payload)))==payload
            assert v.word(u,code_pte)==build.CODE|0x63e
            events.append('restore_entry')
        ins=instructions[pc]
        if ins.mnemonic=='mcr':
            rd=ins.op_str.split(', ')[2]
            value=u.reg_read(getattr(ar,'UC_ARM_REG_'+rd.upper()))
            if r['restore_code_start']<=pc<r['restore_code_start']+r['restore_code_size']:
                assert build.PARAMETERS<=value<build.PARAMETERS+build.PARAMETER_BYTES and value%32==0
                parameter_cleans.append(value)
            elif pc==r['copy_init']+r['copy_symbols']['dma_clean_code_line']:
                assert build.CODE<=value<build.CODE+len(payload) and value%32==0
                code_cleans.append(value)
            elif pc==r['copy_init']+r['copy_symbols']['dma_clean_table_line']:
                assert value==code_pte&~31
            elif pc==first['storage_init']+first['storage_symbols']['handoff_clean_table_line']:
                assert value==ro_pte&~31
            else:assert value==0
            events.append(ins.op_str)
            thumb_mode=bool(u.reg_read(ar.UC_ARM_REG_CPSR)&0x20)
            u.reg_write(ar.UC_ARM_REG_PC,(pc+size)|int(thumb_mode))
        elif ins.mnemonic in ('dsb','isb'):events.append(ins.mnemonic)
    def write(u,access,address,size,value,unused):
        pc=u.reg_read(ar.UC_ARM_REG_PC)
        if l1<=address<l1+0xc000:table_writes.append((address,size,value))
        if r['restore_code_start']<=pc<r['restore_code_start']+r['restore_code_size']:
            if build.SCRATCH<=address<build.STATE:decoded.append((address,size,value))
            elif build.PARAMETERS<=address<build.PARAMETERS+build.PARAMETER_BYTES:restored.append((address,size,value))
    def read(u,access,address,size,value,unused):
        pc=u.reg_read(ar.UC_ARM_REG_PC)
        if r['restore_code_start']<=pc<r['restore_code_start']+r['restore_code_size'] and build.PARAMETERS<=address<build.PARAMETERS+build.PARAMETER_BYTES:
            assert address+size<=read_end
    def publish(u,pc,size,unused):
        assert bytes(u.mem_read(build.PARAMETERS,build.PARAMETER_BYTES))==native
        assert bytes(u.mem_read(build.STATE,116))==bytes(116)
        assert bytes(u.mem_read(build.CODE,len(payload)))==payload
        assert all(u.reg_read(reg)==value for reg,value in saved.items())
        assert events[-1]=='dsb'
        events.append('native_publish')
    hooks=[u.hook_add(UC_HOOK_CODE,step,begin=a,end=a+n-1) for a,n in stages]
    hooks += [u.hook_add(UC_HOOK_CODE,step,begin=r['restore_code_start'],end=r['restore_code_start']+r['restore_code_size']-1),
              u.hook_add(UC_HOOK_MEM_WRITE,write),u.hook_add(UC_HOOK_MEM_READ,read),
              u.hook_add(UC_HOOK_CODE,publish,begin=0x60d368,end=0x60d368)]
    u.reg_write(ar.UC_ARM_REG_CPSR,0x13);u.reg_write(ar.UC_ARM_REG_SP,v.SP)
    try:u.emu_start(0x60d334,0x60d374,count=4000000)
    except Exception:
        print('cold failure PC/registers',hex(u.reg_read(ar.UC_ARM_REG_PC)),[hex(u.reg_read(v.reg(i))) for i in range(16)])
        raise
    assert u.reg_read(ar.UC_ARM_REG_PC)==0x60d374
    for h in hooks:u.hook_del(h)
    words=struct.unpack('<'+'I'*(len(native)//4),native)
    assert decoded==[(build.SCRATCH+4*i,4,w) for i,w in enumerate(words)]
    assert restored==[(build.PARAMETERS+4*i,4,w) for i,w in enumerate(words)]
    assert parameter_cleans==[(build.PARAMETERS+4*i)&~31 for i in range(len(words))]
    assert code_cleans==[(build.CODE+i)&~31 for i in range(0,len(payload),4)]
    expected=bytearray(tables)
    assert table_writes==[(ro_pte,4,v.word(old,ro_pte)&~1),(code_pte,4,build.CODE|0x63e)]
    for a,_,value in table_writes:struct.pack_into('<I',expected,a-l1,value)
    assert bytes(u.mem_read(l1,0xc000))==bytes(expected)
    assert bytes(u.mem_read(boot.START,0x418))==prefix
    assert bytes(u.mem_read(boot.START+0x418,boot.END-boot.START-0x418))==bytes(boot.END-boot.START-0x418)
    assert [v.word(u,c) for c in boot.storage.CELLS]==[0x80,0x80]
    assert bytes(u.mem_read(first['state'],148))==bytes(148)
    assert v.word(u,0x1b85ff8)==0
    assert bytes(u.mem_read(build.STATE+116,build.END-build.STATE-116))==bytes(build.END-build.STATE-116)
    assert bytes(u.mem_read(build.CODE+len(payload),4096-len(payload)))==b'\xa5'*(4096-len(payload))
    skipped=[]
    def reserve(u,pc,size,unused):
        args=[u.reg_read(v.reg(i)) for i in range(4)]
        assert args[1:]==[build.CODE,4096,0],args
        skipped.append(args[1:])
    hook=u.hook_add(UC_HOOK_CODE,reserve,begin=r['allocator_skip_call'],end=r['allocator_skip_call'])
    ranges=oldboot.allocator(u)
    u.hook_del(hook)
    assert skipped==[[build.CODE,4096,0]]
    assert ranges==[row for row in old_ranges if row!=[build.CODE,4096,0]],(ranges,old_ranges)
    assert not any(a<build.CODE+4096 and a+n>build.SCRATCH for a,n,_ in ranges)
    assert v.word(u,boot.FLAG)==1
    assert v.word(u,scratch_pte)==build.SCRATCH|0x41f
    assert v.word(u,pte(r['source']))&1  # Stored bytes never execute from RW data.
    at=events.index('restore_entry')
    assert events[at-8:at]==['dsb','p15, #0, r0, c7, c10, #1','dsb',
        'p15, #0, r0, c8, c3, #0','p15, #0, r0, c7, c1, #0',
        'p15, #0, r0, c7, c1, #6','dsb','isb']
    u.mem_protect(build.CODE,4096,UC_PROT_READ|UC_PROT_EXEC)
    return u,{'mode':mode,'native_parameter_bytes_restored':len(native),'copied_code_bytes':len(payload),
              'parameter_clean_operations':len(parameter_cleans),'code_clean_operations':len(code_cleans),
              'native_parameter_sha256':b.sha(native),'code_rx_state_rw_nx':True,
              'reserved_pages_excluded_from_allocator':True,'whole_page_table_comparison':True,
              'publication_after_restore_and_dsb':True,'restorer_preserves_registers_and_stack':True}


class PlacedIPC(ipc.IPC):
    def code(self,u,pc,size,unused):
        if build.CODE<=pc<build.CODE+self.r['code_size']:return
        super().code(u,pc,size,unused)

    def __init__(self,bundle,cold_machine):
        super().__init__(bundle)
        old=self.u;self.u=cold_machine
        # Only existing runtime services/test model are installed. Never copy
        # component code, CP lease state, publication state or decoded params.
        self.u.mem_map(ipc.AREA,0x10000)
        self.u.mem_write(ipc.AREA,bytes(old.mem_read(ipc.AREA,0x10000)))
        self.u.mem_map(ipc.TRANSPORT,4096);self.u.mem_write(ipc.TRANSPORT,b'\x70\x47')
        for address,n in [(0x120f7c0+12,8),(0x1a7e968,4),(ipc.publication.OBJ,4),(v.G+0xc0,4)]:
            self.u.mem_write(address,bytes(old.mem_read(address,n)))
        self.u.hook_add(UC_HOOK_CODE,self.code)
        self.u.hook_add(UC_HOOK_MEM_READ,self.memory)
        self.u.hook_add(UC_HOOK_MEM_WRITE,self.memory)
        assert bytes(self.u.mem_read(build.STATE,116))==bytes(116)
        assert bytes(self.u.mem_read(self.placement['state'],148))==bytes(148)
        self.open()


def main():
    cp,payload,r=build.make()
    cp2,payload2,r2=build.make();assert cp==cp2 and payload==payload2 and r==r2
    pub=(build.publication.OUT/'publication.bin').read_bytes()
    pubr=json.loads((build.publication.OUT/'component.json').read_text())
    ingress=(build.OUT/'lut_cp_ingress_placed.o')
    # Prototype mappings are created only in a discarded fixture machine.
    # The retained cold machine has neither prototype code nor private state.
    offset=(r['ingress_address']&~1)-build.CODE
    adapter=payload[offset:r['restore_code_start']-build.CODE]
    bundle=(cp,payload,r,pub,pubr,adapter,{'code_bytes':len(adapter)})
    manifest=json.loads((b.HERE/'dev-menu-03/manifest.json').read_text())
    ap=(b.HERE/'dev-menu-03/candidate/appFw.so').read_bytes()
    starts=[]
    for mode in (False,True):
        u,row=cold(cp,payload,r,mode)
        n=PlacedIPC(bundle,u)
        descriptor=ipc.publication.Guarded(ap,manifest,b'\x52'*48124,special=True).execute(system=2)
        token=n.core('lh_cp_reader_begin');assert token
        assert n.deliver(ipc.publication.request(),native_copy=True)[0][15]==1
        assert n.core('lh_cp_reader_end',token)==1
        assert n.deliver(ipc.publication.request(),native_copy=True)[0][15]==0
        packet=ipc.publication.request(op=2)+descriptor
        assert n.deliver(packet,native_copy=True)[0][15]==0
        assert n.deliver(packet)[0][15]==0 and n.publications==1
        assert n.deliver(bytes.fromhex('0500ffff00000000'))==[]
        assert n.original_dispatches==1 and n.bridge_returns==5
        row['cold_to_native_queue_publish_reply']=True
        row['duplicate_publish_runs_once']=True
        row['busy_reader_then_grant_and_unrelated_native_command']=True
        starts.append(row)
    photo_flows=[];native_flows=[]
    for mode in (False,True):
        u,_=cold(cp,payload,r,mode)
        n=photos.Photo(cp,payload,r,cold_machine=u);n.open()
        assert n.run()==(0x48c790,0) and n.snapshot_reads and not n.bits()
        n.finish_vfx();assert n.request()==0
        photo_flows.append({'mode':mode,'cold_photo_snapshot_completion_and_release':True})
        for site in native.SITES:
            for art in (False,True):
                u,_=cold(cp,payload,r,mode)
                n=native.Native(cp,payload,r,site=site,art=art,cold_machine=u);n.open()
                n.invoke();n.invoke()
                kinds=[struct.unpack_from('<I',m)[0] for m in n.queued]
                assert kinds==([1,3,2] if art else [1,2])
                assert n.request()==1
                worker=n.work(cp,payload)
                assert worker.results==[0]*len(kinds) and worker.callback_results==[0]
                assert not n.bits() and n.request()==0
                native_flows.append({'mode':mode,'callsite':hex(site),'art':art,
                                     'cold_native_snapshot_queue_dma_and_release':True})
    report={'status':'PLACED_CP_INGRESS_COLD_RESTORE_AND_MESSAGE_FLOW_VERIFIED_NOT_FLASHABLE',
            'camera_io':False,'in_memory_cp_sha256':r['in_memory_cp_sha256'],
            'recipe_sha256':b.sha((build.OUT/'recipe.json').read_bytes()),'cold_cases':starts,
            'repeat_build_identical':True,'photo_flows':photo_flows,'native_reader_flows':native_flows,
            'source_sha256':{n:b.sha((b.HERE/n).read_bytes()) for n in (
                Path(__file__).name,'verify_lut_cp_ingress.py','verify_lut_cp_publication.py',
                'verify_lut_dma_placement.py','verify_lut_storage.py','verify_lut_photo_reader.py',
                'verify_lut_native_reader.py','verify_lut_reader_placement.py')},
            'limitations':['Physical loader file transfer, CP15 effects, kernel scheduling and remote IPC delivery are boundaries.',
                           'Session is opened by fixture after cold initialization; actual AP owner/session remains pending.',
                           'WBI bypasses cold initialization and remains unsupported by this composition.',
                           'Parameter reads before the exercised cold initialization slice have not been exhaustively excluded.',
                           'No camera installation or full-image release.']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cold_cases':len(starts),'code_bytes':len(payload),'cold_photo_flows':len(photo_flows),'cold_native_flows':len(native_flows)}))


if __name__=='__main__':main()
