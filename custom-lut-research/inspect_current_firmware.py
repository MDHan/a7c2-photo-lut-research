"""Read-only local firmware inventory and selected disassembly. No device APIs."""
import argparse
import hashlib
import importlib.metadata
import json
import struct
from pathlib import Path

import numpy as np
from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

AP_OLD='2ea02f7ecbc5bb917316fe8ef4ce5ffd87eb66efaae78ba2ce11420552df539b'
AP_NOW='1aaeb8fbe0297950cab454d498d1a5ba874f91542aa2737aae27a73971e324d7'
CP_OLD='f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428'
CP_NOW='60a9de1a0636c7f6b5b98607a4d25eeb48634e25294f632743a6d256e583b370'
DELTA=0x108000


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def direct_thumb_calls(raw, targets):
    # Search halfword-aligned BL encodings, then independently check matches
    # with Capstone. This is a direct-call inventory, not a complete CFG.
    halves=np.frombuffer(raw[0x20000:0xb27490],dtype='<u2')
    a,z=halves[:-1].astype('int64'),halves[1:].astype('int64')
    index=np.flatnonzero(((a&0xf800)==0xf000)&((z&0xd000)==0xd000))
    a,z=a[index],z[index]
    sign=(a>>10)&1
    i1=1^((z>>13)&1)^sign
    i2=1^((z>>11)&1)^sign
    displacement=(sign<<24)|(i1<<23)|(i2<<22)|((a&0x3ff)<<12)|((z&0x7ff)<<1)
    displacement=(displacement^(1<<24))-(1<<24)
    va=0x128000+index*2
    dest=va+4+displacement
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    result={}
    for target in targets:
        matches=[]
        for address in va[dest==target]:
            address=int(address)
            insn=next(decoder.disasm(raw[address-DELTA:address-DELTA+4],address,count=1))
            if insn.mnemonic!='bl' or int(insn.op_str.lstrip('#'),16)!=target:
                raise AssertionError('Branch-decoder disagreement')
            matches.append(hex(address))
        result[hex(target)]=matches
    return result


def dump(raw, start, end, decoder, delta=0):
    return '\n'.join(f'{x.address:08x}  {x.mnemonic:10s} {x.op_str}'
                     for x in decoder.disasm(raw[start-delta:end-delta],start))+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    files={}
    for name,relative,expected in [
        ('ap_original','original/appFw.so.bin',AP_OLD),
        ('cp_original','original/cpapp-b.bin.bin',CP_OLD),
        ('ap_fl23','candidate/appFw.so',AP_NOW),
        ('cp_fl23','candidate/cpapp-b.bin',CP_NOW),
    ]:
        path=args.workspace/relative
        raw=path.read_bytes()
        if sha(raw)!=expected:
            raise ValueError('Unexpected local source identity: '+name)
        files[name]=(path,raw)
    ap,cp=files['ap_fl23'][1],files['cp_fl23'][1]
    report={'status':'READ_ONLY_LOCAL_BINARY_INSPECTION','camera_io':False,
            'inputs':{name:{'bytes':len(raw),'sha256':sha(raw)} for name,(_,raw) in files.items()},
            'dependencies':{name:importlib.metadata.version(name) for name in ('capstone','pyelftools','numpy','unicorn')}}
    with files['ap_fl23'][0].open('rb') as stream:
        elf=ELFFile(stream)
        report['ap_machine']=elf['e_machine']
        report['ap_sections']=[{'name':s.name,'va':hex(s['sh_addr']),'file_offset':hex(s['sh_offset']),'bytes':s['sh_size']}
                               for s in elf.iter_sections() if s.name in ('.text','.rodata','.data','.bss')]
    report['ap_look_to_cp_mode']=list(ap[0x352881c:0x352881c+12])
    report['cp_direct_bl_references']=direct_thumb_calls(cp,[0x23d380,0x23dc2c,0x42cd28,0x78aa20,0x24065c])
    report['unmodified_native_ranges']={}
    for name,start,end in [('table_builder',0x135c2c,0x1361f2),
                           ('bank_word_order',0xdbfc20,0xdbfc20+810),
                           ('bank_uploader',0x682a20,0x682ad8)]:
        before=files['cp_original'][1][start:end]
        after=cp[start:end]
        if before!=after:
            raise AssertionError('Expected stock routine/data differs: '+name)
        report['unmodified_native_ranges'][name]={'file_offset':hex(start),'bytes':end-start,'sha256':sha(after),'stock_equals_fl23':True}
    report['last_saved_readbacks']={}
    for name,expected in [('appFw.so',AP_NOW),('cpapp-b.bin',CP_NOW)]:
        paths=sorted((args.workspace/'readback').glob('*-'+name))
        if paths:
            digest=sha(paths[-1].read_bytes())
            report['last_saved_readbacks'][name]={'matches_candidate':digest==expected,'sha256':digest,'live_camera_check':False}
    report['ap_lut_string_anchors']={}
    for text in ('LUT_3D_SIZE','LUT_3D_INPUT_RANGE','/Private/Sony/PRO/LUT','%s/LUT%03d.cube'):
        at=ap.find(text.encode()+b'\0')
        if at<0:
            raise AssertionError('Expected native LUT string missing')
        report['ap_lut_string_anchors'][text]=hex(at)
    # The experimental map is not a full loader reconstruction.
    report['address_caution']='CP listed instruction addresses use the verified local code-window delta 0x108000; this does not prove arbitrary file-backed or BSS storage ownership.'
    args.output.mkdir(mode=0o700)
    (args.output/'inventory.json').write_text(json.dumps(report,indent=2)+'\n')
    thumb=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    arm64=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    spans=[('ap-mode-converter',ap,0x35287f0,0x352881c,arm64,0),
           ('ap-cube-size-parser',ap,0x30206dc,0x3020b00,arm64,0),
           ('cp-table-builder',cp,0x23dc2c,0x23e1f2,thumb,DELTA),
           ('cp-bank-uploader',cp,0x78aa20,0x78aad8,thumb,DELTA),
           ('cp-controller-to-builder',cp,0x23d4b8,0x23d516,thumb,DELTA),
           ('cp-controller-to-transfer',cp,0x23d53a,0x23d5a0,thumb,DELTA),
           ('cp-transfer-to-uploader',cp,0x42cdc0,0x42ce08,thumb,DELTA)]
    for name,raw,start,end,decoder,delta in spans:
        (args.output/(name+'.asm.txt')).write_text(dump(raw,start,end,decoder,delta))
    # Re-read sources after the complete experiment. No source writes are used.
    for name,(path,raw) in files.items():
        if sha(path.read_bytes())!=sha(raw):
            raise AssertionError('Source changed during inspection: '+name)
    print(json.dumps({'status':report['status'],'sources_unchanged':True,'camera_io':False}))


if __name__=='__main__':
    main()
