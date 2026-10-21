"""Place a checked private sender beside the existing AP reply filter.

The actual upload task/session owner remains pending. No full image is saved.
"""
import io
import json
import struct
import subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
import build_lut_handoff_ap as parent
b=parent.b
OUT=b.HERE/'lifecycle-dev/ap-sender-build'
SERVICES={'lh_native_allocate':0x1660060,'lh_native_source':0x165d600,
          'lh_native_send':0x165ead0,'lh_native_free':0x1660350,'lh_native_copy':0x165d3e0}


def make():
    raw,pr=parent.make();OUT.mkdir(exist_ok=True)
    command=['/usr/bin/clang','-target','aarch64-none-elf','-mgeneral-regs-only','-ffreestanding',
             '-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
             '-fno-jump-tables','-Oz','-Wall','-Wextra','-Werror','-c',str(b.HERE/'lut_ap_sender.c'),
             '-o',str(OUT/'lut_ap_sender.o')]
    subprocess.run(command,check=True,capture_output=True,text=True)
    code=(pr['code']+pr['payload_size']+15)&~15
    targets={**SERVICES,'lh_ap_request':pr['code']+pr['symbols']['lh_ap_request']}
    native=ELFFile(io.BytesIO(raw));rela=native.get_section_by_name('.rela.plt')
    imports=native.get_section(rela['sh_link']);plt=native.get_section_by_name('.plt')['sh_addr']
    import_names={plt+32+16*i:imports.get_symbol(x['r_info_sym']).name for i,x in enumerate(rela.iter_relocations())}
    expected={'lh_native_allocate':'osal_valloc_msg_wait','lh_native_source':'osal_set_msg_src',
              'lh_native_send':'osal_snd_msg','lh_native_free':'osal_free_msg','lh_native_copy':'memcpy'}
    assert all(import_names[va]==expected[name] for name,va in SERVICES.items())
    relocations=[]
    with (OUT/'lut_ap_sender.o').open('rb') as f:
        e=ELFFile(f);text=e.get_section_by_name('.text');payload=bytearray(text.data())
        ti=next(i for i,s in enumerate(e.iter_sections()) if s.name=='.text')
        symtab=e.get_section_by_name('.symtab')
        symbols={s.name:s['st_value'] for s in symtab.iter_symbols()
                 if s['st_shndx']==ti and not s.name.startswith('$')}
        for section in e.iter_sections():
            if section.name.startswith(('.data','.bss','.rodata')):assert not section['sh_size']
            if hasattr(section,'iter_relocations'):
                assert section['sh_info']==ti,section.name
                for rel in section.iter_relocations():
                    assert rel['r_info_type']==283 and rel['r_addend']==0  # AArch64 CALL26
                    symbol=symtab.get_symbol(rel['r_info_sym']).name;target=targets[symbol]
                    off=rel['r_offset'];instruction=struct.unpack('<I',b.branch64(code+off,target))[0]|0x80000000
                    struct.pack_into('<I',payload,off,instruction)
                    relocations.append({'offset':off,'symbol':symbol,'target':target})
    end=code+len(payload);elf=ELFFile(io.BytesIO(raw));rx=elf.get_segment(0)
    assert end<=0x51a7718 and raw[code:end]==bytes(len(payload))
    assert (rx['p_memsz']+65535)//65536==(end+65535)//65536
    for s in elf.iter_sections():
        if s['sh_type']!='SHT_NOBITS' and s['sh_size']:
            assert s['sh_offset']+s['sh_size']<=code or s['sh_offset']>=end
        if hasattr(s,'iter_relocations'):
            assert all(not code<=x['r_offset']<end for x in s.iter_relocations())
    changed=bytearray(raw);patches=[]
    for at,data,why in [(code,payload,'checked private request allocation/copy/send'),
                        (0x60,struct.pack('<Q',end),'declared RX file extent'),
                        (0x68,struct.pack('<Q',end),'declared RX memory extent')]:
        patches.append({'offset':at,'length':len(data),'before':raw[at:at+len(data)].hex(),
                        'after':bytes(data).hex(),'purpose':why})
        changed[at:at+len(data)]=data
    undo=bytearray(changed)
    for patch in patches:undo[patch['offset']:patch['offset']+patch['length']]=bytes.fromhex(patch['before'])
    assert bytes(undo)==raw
    combined={k:pr[k] for k in ('code','bridge','state','state_bytes','symbols','bridge_symbols')}
    combined['payload_size']=end-pr['code']
    combined['symbols']={**pr['symbols'],**{k:code-pr['code']+v for k,v in symbols.items()}}
    r={'status':'AP_PRIVATE_SENDER_PLACED_OWNER_NOT_CONNECTED','camera_io':False,'full_image_written':False,
       'code':code,'code_bytes':len(payload),'symbols':symbols,'targets':targets,'relocations':relocations,
       'patches':patches,'inverse_exact':True,'parent_ap_sha256':b.sha(raw),'in_memory_ap_sha256':b.sha(changed),
       'native_imports':{name:import_names[va] for name,va in SERVICES.items()},
       'payload_sha256':b.sha(payload),'compile':command,'parent_recipe_sha256':b.sha((parent.OUT/'recipe.json').read_bytes()),
       'source_sha256':{n:b.sha((b.HERE/n).read_bytes()) for n in
                       (Path(__file__).name,'lut_ap_sender.c','lut_ap_sender.h','lut_handoff_ap.h')},
       'combined_core_layout':combined}
    (OUT/'sender.bin').write_bytes(payload);(OUT/'recipe.json').write_text(json.dumps(r,indent=2)+'\n')
    return bytes(changed),r


if __name__=='__main__':
    _,r=make();print(json.dumps({k:r[k] for k in ('status','code','code_bytes')}))
