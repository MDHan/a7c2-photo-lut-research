"""Cold-copy executable page, allocator exclusion, and real-address DMA hooks."""
import json
import struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ,UC_PROT_READ,UC_PROT_EXEC
from unicorn import arm_const as ar
import build_lut_dma_placement as build
import verify_lut_storage as boot
import verify_cp_handoff_placement as placed
import verify_lut_dma_worker as runtime

v=boot.v


def allocator(u):
    calls=[];control=v.RAM+0x2000
    def at(u,pc,size,unused):
        args=[u.reg_read(v.reg(i)) for i in range(4)]
        assert args[0]==control
        calls.append(args[1:]);u.reg_write(v.reg(0),0)
        u.reg_write(ar.UC_ARM_REG_PC,u.reg_read(ar.UC_ARM_REG_LR))
    hook=u.hook_add(UC_HOOK_CODE,at,begin=0x61a1f4,end=0x61a1f4)
    u.reg_write(ar.UC_ARM_REG_CPSR,0x13);u.reg_write(ar.UC_ARM_REG_SP,v.SP)
    u.reg_write(ar.UC_ARM_REG_LR,v.STOP);u.reg_write(v.reg(0),control)
    u.emu_start(0x619f54,v.STOP,count=30000)
    assert u.reg_read(ar.UC_ARM_REG_PC)==v.STOP
    u.hook_del(hook);return calls


def cold(cp,payload,r,mode):
    parent,_=build.parent.make()
    original,old_tables,_=boot.tables(parent,mode)
    old_ranges=boot.native_memory_ranges(original)
    u,before,info=boot.tables(cp,mode)
    l1=int(info['l1'],16)
    code_pte=placed.pte_address(u,build.CODE)
    ro_pte=placed.pte_address(u,0x10c6000)
    initial_code=v.word(u,code_pte);initial_ro=v.word(u,ro_pte)
    assert initial_code==build.CODE|0x41f
    assert v.word(original,code_pte)==build.CODE|0x433
    expect=bytearray(old_tables);struct.pack_into('<I',expect,code_pte-l1,initial_code)
    assert bytes(expect)==before
    first=json.loads((build.parent.parent.OUT/'recipe.json').read_text())
    stages=[(first['storage_init'],first['storage_size']),(r['copy_init'],r['copy_init_size'])]
    decoder=Cs(CS_ARCH_ARM,CS_MODE_ARM)
    instructions={i.address:i for a,n in stages for i in decoder.disasm(cp[a-build.b.CP_DELTA:a-build.b.CP_DELTA+n],a)}
    events=[];code_cleans=[];table_writes=[];copied=[]
    u.mem_write(boot.START,b'\xa5'*(build.END+32-boot.START))
    v.put(u,boot.START+0x14,boot.FLAG);v.put(u,boot.FLAG,0)
    prefix=bytes(u.mem_read(boot.START,0x418))
    def step(u,pc,size,unused):
        ins=instructions[pc]
        if ins.mnemonic=='mcr':
            if pc==r['copy_init']+r['copy_symbols']['dma_clean_code_line']:
                address=u.reg_read(v.reg(3));code_cleans.append(address)
                assert address%32==0 and build.CODE<=address<build.CODE+len(payload)
                events.append('code_clean')
            else:
                argument=u.reg_read(v.reg(0))
                if pc==r['copy_init']+r['copy_symbols']['dma_clean_table_line']:
                    assert argument==code_pte&~31
                    events.append('new_pte_clean')
                elif pc==first['storage_init']+first['storage_symbols']['handoff_clean_table_line']:
                    assert argument==ro_pte&~31;events.append('ro_pte_clean')
                else:
                    assert argument==0
                    events.append(ins.op_str)
            u.reg_write(ar.UC_ARM_REG_PC,pc+4)
        elif ins.mnemonic in ('dsb','isb'):events.append(ins.mnemonic)
    def write(u,access,address,size,value,unused):
        if l1<=address<l1+0xc000:table_writes.append((address,size,value))
        pc=u.reg_read(ar.UC_ARM_REG_PC)
        if r['copy_init']<=pc<r['copy_init']+r['copy_init_size'] and build.CODE<=address<build.END:
            copied.append((address,size,value))
    def publish(u,pc,size,unused):
        assert bytes(u.mem_read(build.CODE,len(payload)))==payload
        assert v.word(u,build.STATE)==0
        assert [v.word(u,c) for c in boot.storage.CELLS]==[0x80,0x80]
        assert v.word(u,code_pte)==(initial_code&~1)|0x220
        assert events[-1]=='isb'
        events.append('native_publish')
    hooks=[u.hook_add(UC_HOOK_CODE,step,begin=a,end=a+n-1) for a,n in stages]
    hooks += [u.hook_add(UC_HOOK_MEM_WRITE,write),u.hook_add(UC_HOOK_CODE,publish,begin=0x60d368,end=0x60d368)]
    u.reg_write(ar.UC_ARM_REG_CPSR,0x13);u.reg_write(ar.UC_ARM_REG_SP,v.SP)
    u.emu_start(0x60d334,0x60d374,count=4000000)
    assert u.reg_read(ar.UC_ARM_REG_PC)==0x60d374
    for hook in hooks:u.hook_del(hook)
    assert copied==[(build.CODE+i,4,struct.unpack_from('<I',payload,i)[0]) for i in range(0,len(payload),4)]
    assert code_cleans==[(build.CODE+i)&~31 for i in range(0,len(payload),4)]
    assert table_writes==[(ro_pte,4,initial_ro&~1),(code_pte,4,(initial_code&~1)|0x220)]
    expected=bytearray(before)
    for address,_,value in table_writes:struct.pack_into('<I',expected,address-l1,value)
    assert bytes(u.mem_read(l1,0xc000))==bytes(expected)
    assert bytes(u.mem_read(boot.START,0x418))==prefix
    assert bytes(u.mem_read(boot.START+0x418,boot.END-boot.START-0x418))==bytes(boot.END-boot.START-0x418)
    assert bytes(u.mem_read(first['state'],build.CODE-first['state']))==bytes(build.CODE-first['state'])
    assert bytes(u.mem_read(build.CODE+len(payload),4096-len(payload)))==bytes(4096-len(payload))
    assert bytes(u.mem_read(build.END,32))==b'\xa5'*32
    assert v.word(u,boot.FLAG)==1
    assert bytes(u.mem_read(build.SOURCE,len(payload)))==payload
    assert v.word(u,placed.pte_address(u,build.SOURCE))&1
    expected_ranges=[([build.END,0x1000,0] if x==[build.CODE,0x2000,0] else x) for x in old_ranges]
    actual=allocator(u);assert actual==expected_ranges
    assert not any(a<build.END and a+n>build.CODE for a,n,_ in actual)
    u.mem_protect(build.CODE,4096,UC_PROT_READ|UC_PROT_EXEC)
    # Exact encoded sequences follow the first-stage maintenance already
    # verified previously, then clean every copied word's line before the PTE.
    first_end=events.index('isb')+1
    second=events[first_end:]
    assert second[:len(code_cleans)]==['code_clean']*len(code_cleans)
    assert second[len(code_cleans):]==['dsb','new_pte_clean','dsb',
        'p15, #0, r0, c8, c3, #0','p15, #0, r0, c7, c1, #0',
        'p15, #0, r0, c7, c1, #6','dsb','isb','native_publish']
    return u,{'mode':mode,'copied_bytes':len(payload),'code_pte_before':hex(initial_code),
              'code_pte_after':hex(v.word(u,code_pte)),'data_source_never_executable':bool(v.word(u,placed.pte_address(u,build.SOURCE))&1),
              'bss_clear_end':hex(build.END),'code_line_clean_operations':len(code_cleans),
              'code_copy_before_readonly_execute_and_publish':True,
              'only_reserved_page_allocator_range_reduced':True,'remaining_gap':[hex(build.END),4096],
              'prefix_tail_guard_and_existing_state_verified':True,'maintenance_sequence':second}


Original=runtime.Integrated
class Placed(Original):
    def __init__(self,cp,payload,recipe,messages,modes,cold_machine=None):
        super().__init__(cp,payload,recipe,messages,modes)
        self.u.mem_unmap(runtime.build.CODE,4096)
        if cold_machine is None:
            self.u.mem_write(build.CODE,payload)
            self.initialization_fixture=True
        else:
            old=self.u;self.u=cold_machine
            self.u.mem_map(0x2600000,0x100000)
            self.u.mem_write(v.RAM,bytes(old.mem_read(v.RAM,0x10000)))
            for a in (v.STATE,v.DESC,v.RES,v.TOKEN,v.PENDING):self.u.mem_write(a,bytes(old.mem_read(a,4)))
            self.u.hook_add(UC_HOOK_CODE,self.code)
            self.u.hook_add(UC_HOOK_MEM_WRITE,self.memory)
            self.u.hook_add(UC_HOOK_MEM_READ,self.memory)
            assert self.u.mem_read(build.CODE,len(payload))==payload
            assert v.word(self.u,build.STATE)==0
            self.initialization_fixture=False
        self.u.mem_protect(build.CODE,4096,UC_PROT_READ|UC_PROT_EXEC)

    def code(self,u,pc,size,unused):
        r=self.recipe
        if (build.CODE<=pc<build.CODE+r['code_size'] or
                r['run_veneer']<=pc<r['run_veneer']+8 or
                r['dispatch_veneer']<=pc<r['dispatch_veneer']+8):return
        super().code(u,pc,size,unused)


def main():
    cp,payload,r=build.make();again,again_code,again_r=build.make()
    assert cp==again and payload==again_code and r==again_r
    starts=[];end_to_end=[]
    for mode in (False,True):
        machine,result=cold(cp,payload,r,mode);starts.append(result)
        batch=runtime.messages(cp,True)
        n=Placed(cp,payload,r,batch,['success']*3,cold_machine=machine)
        n.loop();assert n.results==[0,0,0] and n.callback_results==[0]
        assert not n.initialization_fixture
        end_to_end.append({'mode':mode,'native_cold_state_and_copied_code_used':True,
                           'native_worker_results':n.results,'application_callbacks':n.callback_results})
    try:
        runtime.Integrated=Placed
        tests=runtime.verify(cp,payload,r)
    finally:runtime.Integrated=Original
    cp_layout=json.loads((build.parent.parent.OUT/'recipe.json').read_text())
    protocol=placed.placed_protocol(cp,cp_layout)
    photos=placed.photo_regression(cp,cp_layout)
    report={'status':'DMA_COLD_COPY_AND_REAL_ADDRESS_WORKER_VERIFIED_NOT_FLASHABLE','camera_io':False,
            'in_memory_cp_sha256':r['in_memory_cp_sha256'],'recipe_sha256':build.b.sha((build.OUT/'recipe.json').read_bytes()),
            'cold_start_cases':starts,'cold_to_worker_cases':end_to_end,'dma_cases':tests,
            'cp_protocol_regression':protocol,'photo_regression':photos,
            'source_sha256':{name:build.b.sha((build.HERE/name).read_bytes()) for name in
                             ('verify_lut_dma_placement.py','verify_lut_dma_worker.py','verify_lut_storage.py',
                              'verify_cp_handoff_placement.py','verify_lut_handoff_cp.py','verify_reusable_entry.py')},
            'limitations':['CP15 effects are explicit recorded boundaries, not physical cache/TLB validation.',
                           'Source file transfer by the bootloader is not executed; native declared extents and startup copying are checked.',
                           'Two cold-to-worker cases use actual native cleared/copied state; the regression matrix uses its verified postcondition fixture.',
                           'OS/DMA/timing remain fixtures; complete callback compatibility, reader leases, IPC/session, WBI and installer remain incomplete.']}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cold_modes':len(starts),'cold_to_worker':len(end_to_end),
                      'dma_cases':len(tests['cases']),'protocol_groups':len(protocol['component_cases'])}))


if __name__=='__main__':main()
