"""Build full offline AP/CP candidate copies. No camera or installer access."""
import argparse, hashlib, io, json, struct, subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_THUMB

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BASE=ROOT/'install-20261018-085012/candidate'
HASHES={'appFw.so':'1aaeb8fbe0297950cab454d498d1a5ba874f91542aa2737aae27a73971e324d7',
        'cpapp-b.bin':'60a9de1a0636c7f6b5b98607a4d25eeb48634e25294f632743a6d256e583b370'}
AP_ENTRY,AP_CODE=0x352c5dc,0x51a6d00
CP_ENTRY,CP_RESULT,CP_CODE=0x48c740,0x48c744,0xc2f490
CP_DELTA=0x108000
sha=lambda b:hashlib.sha256(b).hexdigest()

def branch64(src,dst):
    delta=dst-src
    assert delta%4==0 and -(1<<27)<=delta<(1<<27)
    return struct.pack('<I',0x14000000|((delta//4)&0x3ffffff))

def branch32(src,dst,link=False):
    delta=dst-src-4
    assert delta%2==0 and -(1<<24)<=delta<(1<<24)
    n=delta&0x1ffffff; s=(n>>24)&1
    j1=(1^((n>>23)&1)^s); j2=(1^((n>>22)&1)^s)
    raw=struct.pack('<HH',0xf000|(s<<10)|((n>>12)&0x3ff),
                    (0xd000 if link else 0x9000)|(j1<<13)|(j2<<11)|((n>>1)&0x7ff))
    ins=next(Cs(CS_ARCH_ARM,CS_MODE_THUMB).disasm(raw,src))
    assert ins.mnemonic==('bl' if link else 'b.w') and int(ins.op_str[1:],16)==dst
    return raw

def compile_source(name,target,out):
    source=HERE/name; obj=out/(source.stem+'.o')
    cmd=['/usr/bin/clang','-target',target]
    if target.startswith('armv7'):
        cmd+=['-mthumb','-mcpu=cortex-a9','-mfloat-abi=soft','-mrestrict-it']
    cmd+=['-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables',
          '-fno-asynchronous-unwind-tables','-fno-jump-tables','-Oz','-Wall','-Wextra','-Werror',
          '-c',str(source),'-o',str(obj)]
    subprocess.run(cmd,check=True,capture_output=True,text=True)
    with obj.open('rb') as f:
        e=ELFFile(f); section=e.get_section_by_name('.text'); code=section.data()
        idx=next(i for i,s in enumerate(e.iter_sections()) if s.name=='.text')
        for s in e.iter_sections():
            if hasattr(s,'num_relocations') and s['sh_info']==idx:
                assert s.num_relocations()==0, s.name
            if s.name in ('.data','.bss','.rodata'): assert s['sh_size']==0,s.name
        symbols={s.name:s['st_value'] for s in e.get_section_by_name('.symtab').iter_symbols()
                 if s['st_shndx']==idx and not s.name.startswith('$')}
    return bytearray(code),symbols,{'source':name,'sha256':sha(source.read_bytes()),'command':cmd}

def build(out):
    out.mkdir(parents=True,exist_ok=False)
    artifacts=out/'candidate'; artifacts.mkdir()
    original={n:(BASE/n).read_bytes() for n in HASHES}
    assert all(sha(original[n])==h for n,h in HASHES.items())
    ap,sap,ca=compile_source('ap_entry.S','aarch64-none-elf',out)
    ap[sap['ap_resume']:sap['ap_resume']+4]=branch64(AP_CODE+sap['ap_resume'],AP_ENTRY+4)
    gate,sgate,cgate=compile_source('lut_context_gate.S','aarch64-none-elf',out)
    gate_va=AP_CODE+len(ap)
    at=sgate['lut_context_resume']
    gate[at:at+4]=branch64(gate_va+at,0x303de4c)
    ap+=gate
    cp,scp,cc=compile_source('photo_lut.c','armv7a-none-eabi',out)
    while len(cp)%4: cp+=b'\0'
    guard,sg,cg=compile_source('cp_result.S','armv7a-none-eabi',out)
    guard_va=CP_CODE+len(cp)
    for symbol,target in [('cp_success_branch',0x48c790),('cp_failure_branch',0x48c778),('cp_retry_branch',0x48c74e)]:
        at=sg[symbol];guard[at:at+4]=branch32(guard_va+at,target)
    cp+=guard
    assert CP_CODE+len(cp)<=0xc30000
    assert AP_CODE+len(ap)<=0x51a7718
    result={n:bytearray(b) for n,b in original.items()};patches=[]
    def patch(name,at,old,new,purpose):
        assert len(old)==len(new) and result[name][at:at+len(old)]==old,(purpose,hex(at))
        for p in patches:
            if p['file']==name: assert at+len(old)<=p['offset'] or p['offset']+p['length']<=at
        result[name][at:at+len(old)]=new
        patches.append({'file':name,'offset':at,'offset_hex':hex(at),'length':len(old),
                        'before':old.hex(),'after':new.hex(),'purpose':purpose})
    # AP: explicitly extend RX PT_LOAD into the unallocated file gap. Keep
    # page-rounded extent unchanged and leave all existing sections untouched.
    e=ELFFile(io.BytesIO(original['appFw.so'])); load=e.get_segment(0)
    assert load['p_type']=='PT_LOAD' and load['p_flags']==5 and load['p_vaddr']==load['p_offset']==0
    oldend=load['p_filesz'];newend=AP_CODE+len(ap)
    assert oldend==load['p_memsz']==0x51a6cff
    assert (oldend+0xffff)//0x10000==(newend+0xffff)//0x10000
    for s in e.iter_sections():
        if s['sh_type']!='SHT_NOBITS' and s['sh_size']:
            assert s['sh_offset']+s['sh_size']<=AP_CODE or s['sh_offset']>=newend
        if hasattr(s,'iter_relocations'):
            for r in s.iter_relocations(): assert not AP_CODE<=r['r_offset']<newend
    for offset in (0x60,0x68):
        patch('appFw.so',offset,struct.pack('<Q',oldend),struct.pack('<Q',newend),'RX segment file/memory extent')
    patch('appFw.so',AP_ENTRY,bytes.fromhex('fd7bbba9'),branch64(AP_ENTRY,AP_CODE),'Scoped still-user-LUT entry')
    patch('appFw.so',0x303de48,bytes.fromhex('1f0c0071'),branch64(0x303de48,gate_va),
          'Allow scoped REC_STILL PPLUT in native LUT task constructors')
    # Native option records have 0xb8 stride; +0x60 is internal profile,
    # +0x64 is model property id. +0x1c/+0x1d are still/movie eligibility.
    for profile in range(12,16):
        rec=0x59a22b8+profile*0xb8
        assert struct.unpack_from('<II',original['appFw.so'],rec)==(0x807+profile,)*2
        assert struct.unpack_from('<II',original['appFw.so'],rec+0x60)==(profile,0x66d)
        assert original['appFw.so'][rec+0x1c:rec+0x1e]==b'\0\1'
        patch('appFw.so',rec+0x1c,b'\0',b'\1',f'PPLUT{profile-11} native still-mode option eligibility')
    patch('appFw.so',AP_CODE,bytes(len(ap)),ap,'Position-independent AP entry and displaced prologue')
    # CP: native boot header describes physical offset, byte length and VA.
    # Extend its executable region into its own trailing page; next region's
    # physical offset and VA, all data/BSS locations and file size remain fixed.
    head=0x20000
    assert struct.unpack_from('<6I',original['cpapp-b.bin'],head+0x124)==(0,0xb07490,0x128000,0xb08000,0x496b84,0xc30000)
    size=CP_CODE+len(cp)-0x128000
    patch('cpapp-b.bin',head+0x128,struct.pack('<I',0xb07490),struct.pack('<I',size),'Native executable mapping extent')
    patch('cpapp-b.bin',CP_ENTRY-CP_DELTA,bytes.fromhex('f4f7f2fb'),
          branch32(CP_ENTRY,CP_CODE+(scp['photo_vfx_once']&~1),True),'Actual photo VFX call')
    patch('cpapp-b.bin',CP_RESULT-CP_DELTA,bytes.fromhex('9df84c0010f0010f'),
          branch32(CP_RESULT,guard_va)+bytes.fromhex('00bf00bf'),'Route private LUT failures to native terminal failure')
    patch('cpapp-b.bin',CP_CODE-CP_DELTA,bytes(len(cp)),cp,'Photo LUT entry and result guard in mapped code tail')
    for n,b in result.items():
        assert len(b)==len(original[n]); (artifacts/n).write_bytes(b)
    manifest={'format':1,'status':'OFFLINE_CANDIDATE_HARDWARE_UNVERIFIED','camera_io':False,
        'target':'ILCE-7CM2 2.01 exact local FL23 baseline','inputs':HASHES,
        'outputs':{n:{'sha256':sha(b),'size':len(b)} for n,b in result.items()},
        'build_sources':[ca,cgate,cc,cg], 'compiler':subprocess.check_output(['/usr/bin/clang','--version'],text=True).splitlines()[0],
        'placement':{'ap_entry':AP_ENTRY,'ap_code':AP_CODE,'ap_bytes':len(ap),'cp_call':CP_ENTRY,
                     'ap_lut_context_gate':gate_va,
                     'cp_code':CP_CODE,'cp_bytes':len(cp),'cp_guard':guard_va,'cp_text_length':size,
                     'cp_entry':CP_CODE+(scp['photo_vfx_once']&~1)},'patches':patches}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (out/'SHA256SUMS').write_text(''.join(f"{sha(b)}  candidate/{n}\n" for n,b in result.items()))
    for n,b in [('ap-entry.bin',ap),('cp-entry.bin',cp)]: (out/n).write_bytes(b)
    for n in HASHES: assert sha((BASE/n).read_bytes())==HASHES[n]
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();m=build(a.output)
    print(json.dumps({'candidate':str(a.output/'candidate'),'placement':m['placement'],'outputs':m['outputs']},indent=2))
