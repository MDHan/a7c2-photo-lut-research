"""Wire the real LUT task to an exclusive owner, session and bounded transfer.

A 64 KiB file insertion preserves all original runtime addresses and adds no
RX pages. No camera I/O or deployable full image is emitted by this builder.
"""
import io
import json
import struct
import subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
import build_lut_ap_sender as parent
b=parent.b
OUT=b.HERE/'lifecycle-dev/events-owner-build'
INSERT=65536
NATIVE={'memset':0x165d270,**parent.SERVICES,'lh_native_open':0x165d3c0,'lh_native_read':0x165d4b0,
        'lh_native_close':0x165f430,'lh_native_sleep':0x165ea70,'lh_native_self':0x1660540,
        'lh_native_interchip':0x165d290,'lh_native_load':0x3428510,'lh_native_describe':0x342888c,
        'lh_native_message':0x3537eac,'lh_native_secondary':0x34c6418}


def make():
    raw,pr=parent.make();old=pr['combined_core_layout'];OUT.mkdir(exist_ok=True)
    e=ELFFile(io.BytesIO(raw));rx,rw=e.get_segment(0),e.get_segment(1)
    cut=rw['p_offset'];seed=raw[:cut]+bytes(INSERT)+raw[cut:]
    code=(pr['code']+pr['code_bytes']+15)&~15
    sources=('lut_events_owner.c','lut_events_owner_storage.S');objects=[];compiles=[]
    for source in sources:
        obj=OUT/(Path(source).stem+'.o')
        cmd=['/usr/bin/clang','-target','aarch64-none-elf','-mgeneral-regs-only','-ffreestanding','-fno-builtin',
             '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-jump-tables',
             '-Oz','-Wall','-Wextra','-Werror','-c',str(b.HERE/source),'-o',str(obj)]
        subprocess.run(cmd,check=True,capture_output=True,text=True);compiles.append(cmd)
        with obj.open('rb') as f:
            elf=ELFFile(f);section_data=[];section_base={}
            for i,s in enumerate(elf.iter_sections()):
                if s['sh_flags']&2 and s['sh_size']:
                    assert s.name=='.text' or s.name.startswith('.rodata'),s.name
                    section_data.append((i,s.name,s['sh_addralign'],s.data()))
            syms=elf.get_section_by_name('.symtab')
            symbols=[(s.name,s['st_shndx'],s['st_value']) for s in syms.iter_symbols()]
            relocs=[]
            for s in elf.iter_sections():
                if hasattr(s,'iter_relocations'):
                    for r in s.iter_relocations():relocs.append((s['sh_info'],r['r_offset'],r['r_info_type'],r['r_info_sym'],r['r_addend']))
            objects.append({'data':section_data,'bases':section_base,'symbols':symbols,'relocations':relocs})
    payload=bytearray();targets={**NATIVE,**{k:old['code']+v for k,v in old['symbols'].items()}}
    own_symbols={}
    for obj in objects:
        for index,name,alignment,data in obj['data']:
            payload+=bytes((-len(payload))%max(alignment,4));obj['bases'][index]=code+len(payload);payload+=data
        for name,index,value in obj['symbols']:
            if index in obj['bases'] and name and not name.startswith('$'):
                targets[name]=obj['bases'][index]+value;own_symbols[name]=targets[name]
    resolved=[]
    for obj in objects:
        for section,off,kind,symbol,addend in obj['relocations']:
            name,index,value=obj['symbols'][symbol]
            target=(obj['bases'][index]+value if index in obj['bases'] else targets[name])+addend
            at=obj['bases'][section]+off;offset=at-code
            ins=struct.unpack_from('<I',payload,offset)[0]
            if kind in (282,283):ins=struct.unpack('<I',b.branch64(at,target))[0]|(0x80000000 if kind==283 else 0)
            elif kind==275:
                pages=((target&~4095)-(at&~4095))//4096;assert -(1<<20)<=pages<1<<20
                imm=pages&0x1fffff;ins=(ins&0x9f00001f)|((imm&3)<<29)|((imm>>2)<<5)
            elif kind==277:ins=(ins&~(4095<<10))|((target&4095)<<10)
            else:raise AssertionError((kind,name))
            struct.pack_into('<I',payload,offset,ins);resolved.append([at,kind,name,target])
    state=old['state'];state_bytes=248
    assert (state+16+4095)//4096==(state+state_bytes+4095)//4096
    pagepc=own_symbols['lh_owner_state_page'];imm=(((state&~4095)-(pagepc&~4095))//4096)&0x1fffff
    struct.pack_into('<I',payload,pagepc-code,0x90000000|((imm&3)<<29)|((imm>>2)<<5))
    struct.pack_into('<I',payload,own_symbols['lh_owner_state_offset']-code,0x91000000|((state&4095)<<10))
    struct.pack_into('<I',payload,own_symbols['lh_copy_displaced']-code,struct.unpack_from('<I',raw,0x30210c8)[0])
    payload[own_symbols['lh_copy_resume']-code:own_symbols['lh_copy_resume']-code+4]=b.branch64(own_symbols['lh_copy_resume'],0x30210cc)
    end=code+len(payload)
    assert end<rw['p_vaddr']&~65535,(hex(end),hex(rw['p_vaddr']))
    assert (rx['p_memsz']+65535)//65536==(end+65535)//65536
    assert seed[code:end]==bytes(end-code)
    changed=bytearray(seed);patches=[]
    def patch(at,after,purpose):
        assert all(at+len(after)<=x['offset'] or x['offset']+x['length']<=at for x in patches)
        before=bytes(changed[at:at+len(after)]);assert len(before)==len(after)
        changed[at:at+len(after)]=after
        patches.append({'offset':at,'length':len(after),'before':before.hex(),'after':bytes(after).hex(),'purpose':purpose})
    patch(0x28,struct.pack('<Q',e.header['e_shoff']+INSERT),'section table shifted after file insertion')
    for i,s in enumerate(e.iter_segments()):
        base=e.header['e_phoff']+i*e.header['e_phentsize']
        if s['p_offset']>=cut and s['p_offset']:
            patch(base+8,struct.pack('<Q',s['p_offset']+INSERT),'file offset shifted, runtime address unchanged')
    for i,s in enumerate(e.iter_sections()):
        if s['sh_offset']>=cut and s['sh_offset']:
            at=e.header['e_shoff']+INSERT+i*e.header['e_shentsize']+24
            patch(at,struct.pack('<Q',s['sh_offset']+INSERT),'section file offset shifted')
    patch(0x60,struct.pack('<Q',end),'RX initialized extent')
    patch(0x68,struct.pack('<Q',end),'RX memory extent')
    patch(e.header['e_phoff']+e.header['e_phentsize']+40,struct.pack('<Q',rw['p_memsz']+state_bytes-16),'persistent upload owner BSS')
    for name,resume in [('delete',0x302133c),('delete_cube',0x3021390),('reset',0x34c4a8c)]:
        at=own_symbols['lh_'+name+'_resume']
        payload[at-code:at-code+4]=b.branch64(at,resume)
    patch(code,payload,'upload owner, immutable async storage and monotonic clock shim')
    call=lambda at,name:patch(at,struct.pack('<I',struct.unpack('<I',b.branch64(at,own_symbols[name]))[0]|0x80000000),name)
    assert raw[0x34289a8:0x34289ac]==bytes.fromhex('fd7bbda9')
    patch(0x30210c8,b.branch64(0x30210c8,own_symbols['lh_owner_copy']),'guard shared LUT copy before its first write')
    patch(0x34289a8,b.branch64(0x34289a8,own_symbols['lh_owner_run']),'real LUT sequence task replacement')
    for at,target,name in [(0x3021210,0x34cb5e8,'lh_owner_transfer'),(0x3537f40,0x35358b8,'lh_owner_publish'),(0x342896c,0x34c6418,'lh_owner_secondary')]:
        assert raw[at:at+4]==struct.pack('<I',struct.unpack('<I',b.branch64(at,target))[0]|0x80000000)
        call(at,name)
    call(old['bridge']+old['bridge_symbols']['lh_receive_core_call'],'lh_owner_receive')
    for at,name in [(0x3021338,'lh_menu_delete'),(0x302138c,'lh_menu_delete_cube'),(0x34c4a88,'lh_menu_reset')]:
        patch(at,b.branch64(at,own_symbols[name]),'native delete/reset event enters owner protocol')
    call(0x34c48dc,'lh_menu_reset_legacy')
    # Native task replacement manager invokes virtual slot +0x20 at 3209b28.
    # Patch both stored value and ELF RELATIVE addend, preserving load bias.
    slot=0x5b3db40;file_slot=next(s['p_offset']+slot-s['p_vaddr']+INSERT for s in e.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=slot<s['p_vaddr']+s['p_filesz'])
    patch(file_slot,struct.pack('<Q',own_symbols['lh_menu_cancel']),'select_lut native cancellation virtual slot')
    found=0
    for section in e.iter_sections():
        if hasattr(section,'iter_relocations'):
            for index,rel in enumerate(section.iter_relocations()):
                if rel['r_offset']==slot:
                    assert rel['r_info_type']==1027 and rel['r_addend']==0x303c42c
                    at=section['sh_offset']+index*section['sh_entsize']+16
                    patch(at,struct.pack('<Q',own_symbols['lh_menu_cancel']),'cancel virtual slot relocation follows load bias');found+=1
    assert found==1

    inverse=bytearray(changed)
    for p in patches:inverse[p['offset']:p['offset']+p['length']]=bytes.fromhex(p['before'])
    assert bytes(inverse)==seed and bytes(inverse[:cut]+inverse[cut+INSERT:])==raw
    ne=ELFFile(io.BytesIO(changed))
    for before,after in zip(e.iter_sections(),ne.iter_sections(),strict=True):
        assert before.name==after.name and before['sh_addr']==after['sh_addr'] and before['sh_size']==after['sh_size']
        if before['sh_type']!='SHT_NOBITS' and before['sh_size']:
            olddata=raw[before['sh_offset']:before['sh_offset']+before['sh_size']]
            newdata=bytes(changed[after['sh_offset']:after['sh_offset']+after['sh_size']])
            # Only four exact native instructions are changed inside sections.
            if before.name not in ('.text','.data.rel.ro','.rela.dyn'):assert newdata==olddata,before.name
    for before,after in zip(e.iter_segments(),ne.iter_segments(),strict=True):
        assert before['p_vaddr']==after['p_vaddr'] and before['p_flags']==after['p_flags']
        assert before['p_vaddr']%65536==after['p_offset']%65536 if before['p_type']=='PT_LOAD' else True
    r={'status':'REAL_UPLOAD_TASK_OWNER_PENDING_INTEGRATION_VERIFICATION','camera_io':False,'full_image_written':False,
       'parent_ap_sha256':b.sha(raw),'in_memory_ap_sha256':b.sha(changed),'code':code,'code_size':len(payload),
       'state':state,'state_bytes':state_bytes,'symbols':own_symbols,'relocations':resolved,'patches':patches,
       'file_insertion':{'offset':cut,'bytes':INSERT},'all_original_runtime_addresses_unchanged':True,
       'rx_and_rw_page_extents_unchanged':True,'inverse_to_parent_exact':True,
       'core_layout':{**old,'payload_size':end-old['code']},'native_targets':NATIVE,'compiles':compiles,
       'payload_sha256':b.sha(payload),'parent_recipe_sha256':b.sha((parent.OUT/'recipe.json').read_bytes()),
       'source_sha256':{n:b.sha((b.HERE/n).read_bytes()) for n in
                       (Path(__file__).name,'lut_events_owner.c','lut_events_owner.h','lut_events_owner_storage.S')}}
    (OUT/'owner.bin').write_bytes(payload);(OUT/'recipe.json').write_text(json.dumps(r,indent=2)+'\n')
    return bytes(changed),r


if __name__=='__main__':
    _,r=make();print(json.dumps({k:r[k] for k in ('status','code_size','state_bytes')}))
