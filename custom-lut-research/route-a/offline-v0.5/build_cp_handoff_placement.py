"""Compose CP lease code/storage with reusable photo entry, in memory only.

No native lease reader/IPC hooks yet; this adds cold-start code placement.
"""
import io
import json
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_GRP_JUMP,CS_GRP_CALL
from capstone.arm import ARM_OP_IMM,ARM_OP_MEM,ARM_REG_PC
from elftools.elf.elffile import ELFFile
import build as b
import build_lifecycle_storage as storage
import build_reusable_entry as reuse
import build_lut_handoff_cp as lease

HERE=b.HERE
OUT=HERE/'lifecycle-dev/cp-placement-build'
RO_CODE=0x10c6b84
SPLIT=0x104
CP_STATE=storage.STATE_BASE+8
CP_END=CP_STATE+148


def check_split(code):
    # Mapping symbols distinguish literal pools from Thumb instructions.
    with (lease.OUT/'lut_handoff_cp.o').open('rb') as f:
        e=ELFFile(f)
        marks=sorted((s['st_value'],s.name) for s in e.get_section_by_name('.symtab').iter_symbols()
                     if s.name.startswith(('$t','$d')))
    marks.append((len(code),'end'))
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB);decoder.detail=True
    branches=literals=0
    for (lo,kind),(hi,_) in zip(marks,marks[1:]):
        if not kind.startswith('$t'):continue
        instructions=list(decoder.disasm(code[lo:hi],lo))
        assert sum(i.size for i in instructions)==hi-lo
        for ins in instructions:
            span=(0,SPLIT) if ins.address<SPLIT else (SPLIT,len(code))
            for op in ins.operands:
                if (ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL)) and op.type==ARM_OP_IMM:
                    assert span[0]<=op.imm<span[1],(hex(ins.address),ins.op_str)
                    branches+=1
                if op.type==ARM_OP_MEM and op.mem.base==ARM_REG_PC:
                    target=((ins.address+4)&~3)+op.mem.disp
                    assert span[0]<=target and target+4<=span[1]
                    literals+=1
            assert ins.mnemonic!='adr','additional PC-relative instruction needs audit'
    return {'partition_boundary':SPLIT,'internal_branch_targets_checked':branches,
            'literal_loads_checked':literals,'mapping_symbols':marks[:-1]}


def make():
    OUT.mkdir(exist_ok=True)
    old,rm=reuse.make()
    code,cm=lease.make()
    assert cm['symbols']['lh_cp_reader_end']&~1==SPLIT
    split=check_split(code)
    raw=(HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    assert b.sha(raw)==storage.CP_HASH
    init,sy,compile_init=b.compile_source('lut_handoff_storage.S','armv7a-none-eabi',OUT)
    assert len(init)==96
    at=rm['addresses']['storage']
    assert rm['addresses']['retry']==at+rm['sizes']['storage']
    retry_size=rm['sizes']['retry'];assert retry_size==12
    retry=bytearray(old[rm['addresses']['retry']-b.CP_DELTA:rm['addresses']['retry']-b.CP_DELTA+retry_size])
    new_retry=at+len(init)
    retry_branch=rm['symbols']['retry']['lut_idle_release_resume']
    retry[retry_branch:retry_branch+4]=b.branch32(new_retry+retry_branch,0x4e7f90)
    init[sy['handoff_storage_resume']:sy['handoff_storage_resume']+4]=storage.arm_branch(at+sy['handoff_storage_resume'],0x60d35c)
    left=new_retry+retry_size
    text_end=left+SPLIT
    ro_end=RO_CODE+len(code)-SPLIT
    assert text_end<=0xc30000 and ro_end<=0x10c7000
    assert CP_END==0x1b85ff8
    assert struct.unpack_from('<3I',raw,0x20130)==(0xb08000,0x496b84,0xc30000)
    assert struct.unpack_from('<3I',raw,0x2013c)==(0xf9f000,0x142aa0,0x10c7000)
    assert raw[RO_CODE-b.CP_DELTA:ro_end-b.CP_DELTA]==bytes(ro_end-RO_CODE)
    result=bytearray(old)
    result[at-b.CP_DELTA:text_end-b.CP_DELTA]=init+retry+code[:SPLIT]
    result[RO_CODE-b.CP_DELTA:ro_end-b.CP_DELTA]=code[SPLIT:]
    struct.pack_into('<I',result,0x20128,text_end-0x128000)
    struct.pack_into('<I',result,0x20134,ro_end-0xc30000)
    struct.pack_into('<I',result,0x2014c,CP_END-storage.BSS_START)
    assert struct.unpack_from('<I',old,0x60d338-b.CP_DELTA)[0]==0xe3053f64
    struct.pack_into('<I',result,0x60d338-b.CP_DELTA,0xe3053ff8)
    result[0x4e7f50-b.CP_DELTA:0x4e7f54-b.CP_DELTA]=b.branch32(0x4e7f50,new_retry)
    # Retain the original BSS-init branch address. Init is expanded in place.
    assert result[0x60d358-b.CP_DELTA:0x60d35c-b.CP_DELTA]==storage.arm_branch(0x60d358,at)
    windows=[(p['offset'],p['offset']+p['length']) for p in rm['patches']]
    windows += [(at-b.CP_DELTA,text_end-b.CP_DELTA),(RO_CODE-b.CP_DELTA,ro_end-b.CP_DELTA),(0x20134,0x20138)]
    merged=[]
    for a,z in sorted(windows):
        if merged and a<=merged[-1][1]:merged[-1][1]=max(z,merged[-1][1])
        else:merged.append([a,z])
    patches=[];undo=bytearray(result)
    for a,z in merged:
        if raw[a:z]==result[a:z]:continue
        patches.append({'offset':a,'length':z-a,'before':raw[a:z].hex(),'after':bytes(result[a:z]).hex()})
        undo[a:z]=raw[a:z]
    assert bytes(undo)==raw and len(result)==len(raw)
    symbols={name:(left+off if (off&~1)<SPLIT else RO_CODE+off-SPLIT) for name,off in cm['symbols'].items()}
    report={'status':'CP_COLD_PLACEMENT_EXPERIMENT_NOT_READY_TO_FLASH','camera_io':False,
            'base_cp_sha256':storage.CP_HASH,'in_memory_cp_sha256':b.sha(result),'full_image_written':False,
            'core_addresses':symbols,'state':CP_STATE,'state_end':CP_END,'state_bytes':148,
            'left_code':left,'left_size':SPLIT,'right_code':RO_CODE,'right_size':len(code)-SPLIT,
            'text_end':text_end,'ro_end':ro_end,'execute_page':0x10c6000,
            'storage_init':at,'storage_symbols':sy,'storage_size':len(init),'retry':new_retry,
            'split_verification':split,'patches':patches,'inverse_exact':True,
            'component_sha256':b.sha((lease.OUT/'component.json').read_bytes()),
            'reuse_recipe_sha256':b.sha((reuse.OUT/'recipe.json').read_bytes()),
            'compile_init':compile_init,
            'source_sha256':{name:b.sha((HERE/name).read_bytes()) for name in
                             ('build_cp_handoff_placement.py','lut_handoff_storage.S')}}
    (OUT/'text-tail.bin').write_bytes(result[b.CP_CODE-b.CP_DELTA:text_end-b.CP_DELTA])
    (OUT/'ro-tail.bin').write_bytes(code[SPLIT:])
    (OUT/'recipe.json').write_text(json.dumps(report,indent=2)+'\n')
    return bytes(result),report


if __name__=='__main__':
    _,r=make();print(json.dumps({k:r[k] for k in ('text_end','ro_end','state_end','in_memory_cp_sha256')}))
