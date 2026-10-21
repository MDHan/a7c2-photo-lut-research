"""Verify actual split CP placement, cold initialization and lease behavior.

CP15 cache/TLB effects are recorded boundaries, not hardware emulation.
"""
import hashlib
import json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn import arm_const as ar
import build_cp_handoff_placement as build
import build_lut_handoff_cp as lease
import build_lut_handoff_ap as ap_build
import verify_lut_storage as boot
import verify_lut_handoff_cp as protocol
import verify_reusable_entry as photo
from verify_shared_buffer_interleaving import Receiver

v=boot.v
HERE=build.HERE


def pte_address(u,va):
    l1=v.word(u,0x108f1c)
    pde=v.word(u,l1+(va>>20)*4)
    assert pde&3==1
    return (pde&~1023)+((va>>12)&255)*4


def cold(cp,r,mode):
    baseline=(HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    original,original_tables,_=boot.tables(baseline,mode)
    original_ranges=boot.native_memory_ranges(original)
    u,before_tables,info=boot.tables(cp,mode)
    assert before_tables==original_tables
    l1=int(info['l1'],16)
    pte=pte_address(u,r['execute_page']);old_pte=v.word(u,pte)
    assert old_pte&1
    # Both page-table pages retain their native attributes (0x417), distinct
    # from normal cached data (0x41f). No page-table memory remap is introduced.
    table_page_pte=v.word(u,pte_address(u,pte))
    assert table_page_pte&0xfff==0x417
    start,end=boot.START,r['state_end']
    u.mem_write(start,b'\xa5'*(end+32-start))
    v.put(u,start+0x14,boot.FLAG);v.put(u,boot.FLAG,0)
    prefix=bytes(u.mem_read(start,0x418))
    events=[];writes=[]
    decoder=Cs(CS_ARCH_ARM,CS_MODE_ARM)
    init=r['storage_init']
    insns={i.address:i for i in decoder.disasm(cp[init-0x108000:init-0x108000+r['storage_size']],init)}
    expected_mcr={init+r['storage_symbols'][name]:operation for name,operation in
                  [('handoff_clean_table_line','DCCMVAC'),('handoff_invalidate_tlb','TLBIALLIS'),
                   ('handoff_invalidate_icache','ICIALLUIS'),('handoff_invalidate_predictor','BPIALLIS')]}
    def init_hook(u,pc,size,unused):
        ins=insns[pc]
        if pc==init+r['storage_symbols']['handoff_pte_store']:
            assert u.reg_read(v.reg(0))==pte
            assert u.reg_read(v.reg(1))==old_pte&~1
            events.append('pte_store')
        if pc in expected_mcr:
            assert ins.mnemonic=='mcr'
            name=expected_mcr[pc]
            argument=u.reg_read(v.reg(0))
            assert argument==(pte&~31 if name=='DCCMVAC' else 0)
            assert v.word(u,pte)==old_pte&~1
            events.append(name)
            u.reg_write(ar.UC_ARM_REG_PC,pc+4)
        elif ins.mnemonic in ('dsb','isb'):events.append(ins.mnemonic)
    def publish(u,pc,size,unused):
        if pc==0x60d368:
            assert events==['pte_store','DCCMVAC','dsb','TLBIALLIS','ICIALLUIS','BPIALLIS','dsb','isb']
            assert [v.word(u,c) for c in boot.storage.CELLS]==[0x80,0x80]
            assert bytes(u.mem_read(r['state'],148))==bytes(148)
            events.append('publish')
        elif pc==0x60d36c:events.append('native_dsb')
        elif pc==0x60d370:events.append('sev')
    def write(u,access,address,size,value,unused):writes.append([address,size,value])
    hooks=[u.hook_add(UC_HOOK_CODE,init_hook,begin=init,end=init+r['storage_size']-1),
           u.hook_add(UC_HOOK_CODE,publish,begin=0x60d368,end=0x60d370),
           u.hook_add(UC_HOOK_MEM_WRITE,write,begin=l1,end=l1+0xc000-1)]
    u.reg_write(ar.UC_ARM_REG_CPSR,0x13);u.reg_write(ar.UC_ARM_REG_SP,v.SP)
    u.emu_start(0x60d334,0x60d374,count=4000000)
    assert u.reg_read(ar.UC_ARM_REG_PC)==0x60d374
    for hook in hooks:u.hook_del(hook)
    assert writes==[[pte,4,old_pte&~1]],writes
    expected=bytearray(before_tables)
    import struct
    struct.pack_into('<I',expected,pte-l1,old_pte&~1)
    assert bytes(u.mem_read(l1,0xc000))==expected
    assert bytes(u.mem_read(start,0x418))==prefix
    assert bytes(u.mem_read(start+0x418,boot.END-start-0x418))==bytes(boot.END-start-0x418)
    assert bytes(u.mem_read(end,32))==b'\xa5'*32
    assert v.word(u,boot.FLAG)==1
    assert boot.native_memory_ranges(u)==original_ranges
    return {'mode':mode,'pte_address':hex(pte),'before_pte':hex(old_pte),'after_pte':hex(old_pte&~1),
            'table_page_attributes':hex(table_page_pte&0xfff),'events':events,
            'only_one_pte_changed':True,'permissions_except_xn_unchanged':True,
            'bss_prefix_and_end_guard_preserved':True,'allocator_requests_unchanged':True}


def placed_protocol(cp,r):
    code,cm=lease.make()
    original_cls,original_state=protocol.Cp,protocol.STATE
    class Placed(original_cls):
        def __init__(self,cp_image,unused_code,unused_recipe):
            Receiver.__init__(self,cp_image)
            self.recipe={'symbols':{name:address-protocol.CODE for name,address in r['core_addresses'].items()}}
            self.u.mem_write(r['state'],bytes(148))
            for page in (r['left_code']&~4095,r['right_code']&~4095):
                self.u.mem_protect(page,4096,UC_PROT_READ|UC_PROT_EXEC)
            self.u.mem_protect(r['state']&~4095,4096,UC_PROT_READ|UC_PROT_WRITE)
        def code(self,u,pc,size,unused):
            if r['left_code']<=pc<r['left_code']+r['left_size'] or r['right_code']<=pc<r['right_code']+r['right_size']:
                return
            Receiver.code(self,u,pc,size,unused)
    try:
        protocol.Cp,protocol.STATE=Placed,r['state']
        cases,malformed=protocol.component_cases(cp,code,cm)
        ap,am=ap_build.make()
        paired=protocol.paired(ap,am,cp,code,cm)
    finally:protocol.Cp,protocol.STATE=original_cls,original_state
    return {'component_cases':cases,'malformed_cases':len(malformed),'paired_cases':paired,
            'actual_split_addresses_executed':True,'state_at_declared_bss_address':True,
            'new_code_pages_enforced_read_execute_in_emulator':True,
            'new_state_page_enforced_read_write_in_emulator':True}


def photo_regression(cp,r):
    m=json.loads((build.reuse.OUT/'recipe.json').read_text())
    old_payload=(build.reuse.OUT/'composed-payload.bin').read_bytes()
    prefix=r['storage_init']-build.b.CP_CODE
    assert cp[build.b.CP_CODE-0x108000:r['storage_init']-0x108000]==old_payload[:prefix]
    # The full cold state was checked above twice. Supply its resulting cell
    # bytes here instead of rerunning the unrelated entire BSS clear per shot.
    original=photo.old.storage_test.cold_init
    def cold_postcondition(u,modified):
        assert modified
        for cell in boot.storage.CELLS:v.put(u,cell,0x80)
        u.mem_write(r['state'],bytes(148))
    results=[]
    try:
        photo.old.storage_test.cold_init=cold_postcondition
        for context in (0,1):
            for kind,mask in ((3,1),(9,15)):
                n=photo.Photo(cp,m,context,kind,mask)
                for epoch in (1,2):
                    assert n.run()==(0x48c790,0)
                    n.check_descriptors(epoch*0x1000|2)
                    n.finish_vfx()
                    assert v.word(n.u,n.cell)==epoch*0x1000
                    n.prepare_next()
                results.append({'context':context,'kind':kind,'mask':mask,'captures':2})
        for mode,code in [('load_callback_failure',2),('submit_failure',10)]:
            n=photo.Photo(cp,m,mode=mode)
            assert n.run()==(0x48c778,0xc17e0000|code)
            if mode=='submit_failure':n.finish_vfx()
            assert v.word(n.u,n.cell)&0x40
            results.append({'mode':mode,'fault_retained':True})
    finally:photo.old.storage_test.cold_init=original
    for ready in (False,True):
        n=photo.retry.Retry(cp,r['retry'],12,ready=ready)
        n.u.mem_write(v.PENDING,b'\0');v.put(n.u,photo.retry.owner.USESTATE,1)
        n.idle_prefix(0,[0]*4)
        assert v.word(n.u,photo.retry.owner.USESTATE)==(2 if ready else 1)
        results.append({'relocated_retry_ready':ready,'native_result_preserved':True})
    return {'unchanged_photo_code_prefix':True,'cases':results,
            'initial_state_is_verified_cold_postcondition_fixture':True}


def main():
    cp,r=build.make();again,rr=build.make();assert cp==again and r==rr
    starts=[cold(cp,r,mode) for mode in (False,True)]
    tests=placed_protocol(cp,r)
    photos=photo_regression(cp,r)
    report={'status':'CP_SPLIT_PLACEMENT_AND_COLD_INIT_OFFLINE_VERIFIED_NOT_FLASHABLE','camera_io':False,
            'in_memory_cp_sha256':r['in_memory_cp_sha256'],
            'recipe_sha256':hashlib.sha256((build.OUT/'recipe.json').read_bytes()).hexdigest(),
            'cold_start_cases':starts,'protocol_at_placed_addresses':tests,
            'photo_regression':photos,
            'limitations':['cache/TLB CP15 effects are explicit recorded boundaries; no real hardware coherency test',
                           'page-table generation and BSS clearing execute native code; actual bootloader file transfer is not run',
                           'native reader/IPC hooks, startup session, deadlines, WBI and installer are still incomplete'],
            'source_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
                            ('verify_cp_handoff_placement.py','verify_lut_storage.py','verify_lut_handoff_cp.py',
                             'verify_reusable_entry.py','verify_release_retry.py')}}
    (build.OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'cold_start_modes':len(starts),'component_groups':len(tests['component_cases']),
                      'malformed_cases':tests['malformed_cases'],'paired_cases':len(tests['paired_cases']),
                      'status':report['status']}))


if __name__=='__main__':main()
