"""Compose the AP private-reply filter only, in memory; no camera/image output.

Upload owner, CP reader/write gate and session bootstrap are NOT connected.
Cold-loaded declared BSS stays uninitialized until an explicit session open.
"""
import hashlib
import io
import json
import struct
import subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
import build as b

HERE=b.HERE
OUT=HERE/'lifecycle-dev/handoff-build'
BASE_HASH='5e0741cf58f4125f7b6f5950b5d13d47be025052c9dcc1a799e2ce004cd32c93'


def compile_core():
    source=HERE/'lut_handoff_ap.c'; obj=OUT/'lut_handoff_ap.o'
    cmd=['/usr/bin/clang','-target','aarch64-none-elf','-mgeneral-regs-only',
         '-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables',
         '-fno-asynchronous-unwind-tables','-fno-jump-tables','-Oz','-Wall','-Wextra',
         '-Werror','-c',str(source),'-o',str(obj)]
    subprocess.run(cmd,check=True,capture_output=True,text=True)
    with obj.open('rb') as f:
        e=ELFFile(f); section=e.get_section_by_name('.text')
        idx=next(i for i,s in enumerate(e.iter_sections()) if s.name=='.text')
        for s in e.iter_sections():
            if hasattr(s,'num_relocations'): assert s.num_relocations()==0,s.name
            if s.name.startswith(('.data','.bss','.rodata')): assert s['sh_size']==0,s.name
        symbols={s.name:s['st_value'] for s in e.get_section_by_name('.symtab').iter_symbols()
                 if s['st_shndx']==idx and not s.name.startswith('$')}
        return bytearray(section.data()),symbols,cmd


def make():
    OUT.mkdir(exist_ok=True)
    original=(HERE/'dev-menu-03/candidate/appFw.so').read_bytes()
    assert b.sha(original)==BASE_HASH
    e=ELFFile(io.BytesIO(original));rx=e.get_segment(0);rw=e.get_segment(1)
    assert rx['p_flags']==5 and rx['p_vaddr']==rx['p_offset']==0
    assert rw['p_type']=='PT_LOAD' and rw['p_flags']==6
    core,symbols,cmd=compile_core()
    bridge,bs,bmeta=b.compile_source('lut_handoff_receive.S','aarch64-none-elf',OUT)
    code=(rx['p_filesz']+15)&~15
    bridge_va=code+len(core)
    end=bridge_va+len(bridge)
    state=rw['p_vaddr']+rw['p_memsz']
    assert state%16==0
    assert end<=0x51a7718
    assert (rx['p_filesz']+0xffff)//0x10000==(end+0xffff)//0x10000
    assert (state+4095)//4096==(state+16+4095)//4096
    for s in e.iter_sections():
        if s['sh_type']!='SHT_NOBITS' and s['sh_size']:
            assert s['sh_offset']+s['sh_size']<=code or s['sh_offset']>=end
        if hasattr(s,'iter_relocations'):
            for r in s.iter_relocations():
                assert not code<=r['r_offset']<end
                assert not state<=r['r_offset']<state+16
    def branch(symbol,target,link=False):
        off=bs[symbol]
        ins=struct.unpack('<I',b.branch64(bridge_va+off,target))[0]
        struct.pack_into('<I',bridge,off,ins|(0x80000000 if link else 0))
    branch('lh_receive_length_call',0x165e770,True)
    branch('lh_receive_core_call',code+symbols['lh_ap_receive'],True)
    branch('lh_receive_resume',0x3531598)
    branch('lh_receive_consumed',0x35316cc)
    pc=bridge_va+bs['lh_receive_state_page']
    pages=((state&~4095)-(pc&~4095))//4096
    assert -(1<<20)<=pages<(1<<20)
    imm=pages&0x1fffff
    struct.pack_into('<I',bridge,bs['lh_receive_state_page'],0x90000000|((imm&3)<<29)|((imm>>2)<<5))
    struct.pack_into('<I',bridge,bs['lh_receive_state_offset'],0x91000000|((state&4095)<<10))
    payload=core+bridge
    assert original[code:end]==bytes(len(payload))
    assert original[0x3531594:0x3531598]==bytes.fromhex('60024039')
    result=bytearray(original);patches=[]
    def patch(off,data,purpose):
        assert all(off+len(data)<=p['offset'] or p['offset']+p['length']<=off for p in patches)
        patches.append({'offset':off,'length':len(data),'before':original[off:off+len(data)].hex(),
                        'after':bytes(data).hex(),'purpose':purpose})
        result[off:off+len(data)]=data
    patch(code,payload,'private reply core and receiving bridge')
    patch(0x3531594,b.branch64(0x3531594,bridge_va),'private reply dispatch before generic futures')
    for off in (0x60,0x68):patch(off,struct.pack('<Q',end),'RX extent')
    rw_memsz_offset=e.header['e_phoff']+e.header['e_phentsize']+40
    assert struct.unpack_from('<Q',original,rw_memsz_offset)[0]==rw['p_memsz']
    patch(rw_memsz_offset,struct.pack('<Q',rw['p_memsz']+16),'declare private AP state in BSS')
    undo=bytearray(result)
    for p in patches:undo[p['offset']:p['offset']+p['length']]=bytes.fromhex(p['before'])
    assert bytes(undo)==original and len(result)==len(original)
    report={'status':'EXPERIMENTAL_AP_REPLY_FILTER_NOT_READY_TO_FLASH','camera_io':False,
            'base_ap_sha256':BASE_HASH,'in_memory_ap_sha256':b.sha(result),'full_image_written':False,
            'code':code,'bridge':bridge_va,'state':state,'state_bytes':16,'payload_size':len(payload),
            'rx_64k_page_extent_unchanged':True,'rw_4k_page_extent_unchanged':True,
            'symbols':symbols,'bridge_symbols':bs,'patches':patches,'inverse_exact':True,
            'core_compile_command':cmd,'bridge_compile':bmeta,
            'source_sha256':{name:b.sha((HERE/name).read_bytes()) for name in
                             ('lut_handoff_ap.h','lut_handoff_ap.c','lut_handoff_receive.S','build_lut_handoff_ap.py')}}
    (OUT/'ap-reply-filter.bin').write_bytes(payload)
    (OUT/'recipe.json').write_text(json.dumps(report,indent=2)+'\n')
    return bytes(result),report


if __name__=='__main__':
    _,r=make();print(json.dumps({k:r[k] for k in ('payload_size','state','status')}))
