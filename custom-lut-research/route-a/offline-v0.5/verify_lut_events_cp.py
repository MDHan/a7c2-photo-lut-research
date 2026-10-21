"""Native cold copy, exact parameter restore and placed CP receive loop."""
import json
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ,UC_PROT_READ,UC_PROT_EXEC
from unicorn import arm_const as ar
import build_lut_events_cp as build
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
    assert decoded==[(build.SCRATCH+i,1,w) for i,w in enumerate(native)]
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

