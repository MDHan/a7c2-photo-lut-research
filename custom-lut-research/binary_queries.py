"""Small offline binary queries; conservative references, not a complete CFG."""
from pathlib import Path
import struct
import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB

BASE=Path(__file__).resolve().parents[1]/'install-20261018-085012/candidate'
AP=(BASE/'appFw.so').read_bytes()
CP=(BASE/'cpapp-b.bin').read_bytes()
A64=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
THUMB=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
TEXT_START,TEXT_END=0x1660680,0x37041a0
_words=np.frombuffer(AP[TEXT_START:TEXT_END],dtype='<u4')
_ix=np.flatnonzero((_words&0x9f000000)==0x90000000)
_v=_words[_ix].astype('int64')
_imm=((_v>>29)&3)|(((_v>>5)&0x7ffff)<<2)
_imm=(_imm^(1<<20))-(1<<20)
_pc=TEXT_START+_ix*4
_page=(_pc&~4095)+(_imm<<12)


def a64_refs(target,span=48):
    results=[]
    for pc in _pc[_page==(target&~4095)]:
        pc=int(pc)
        reg=struct.unpack_from('<I',AP,pc)[0]&31
        for insn in A64.disasm(AP[pc+4:pc+span],pc+4):
            word=struct.unpack_from('<I',AP,insn.address)[0]
            if word&0xffc00000==0x91000000 and (word>>5)&31==reg:
                offset=(word>>10)&4095
                if target&4095==offset:
                    results.append((pc,insn.address))
            # References are candidates; nearby clobbers may invalidate them.
    return results


def a64_calls(target):
    index=np.flatnonzero((_words&0x7c000000)==0x14000000)
    imm=(_words[index]&0x3ffffff).astype('int64')
    imm=(imm^(1<<25))-(1<<25)
    va=TEXT_START+index*4
    return [int(x) for x in va[va+imm*4==target]]


_halves=np.frombuffer(CP[0x20000:0xb27490],dtype='<u2')


def thumb_refs(target,span=48):
    results=[]
    h=_halves
    index=np.flatnonzero((h[:-1]&0xfbf0)==0xf240)
    a,z=h[index].astype('int64'),h[index+1].astype('int64')
    imm=((a&15)<<12)|(((a>>10)&1)<<11)|(((z>>12)&7)<<8)|(z&255)
    for i in index[imm==(target&65535)]:
        file=0x20000+int(i)*2
        first=next(THUMB.disasm(CP[file:file+4],file+0x108000,count=1))
        reg=first.op_str.split(',')[0]
        for insn in THUMB.disasm(CP[file+4:file+span],file+4+0x108000):
            if insn.mnemonic=='movt' and insn.op_str==reg+', #'+hex(target>>16):
                results.append((first.address,insn.address))
                break
    return results


def disasm(kind,start,end):
    raw,decoder,delta=(AP,A64,0) if kind=='ap' else (CP,THUMB,0x108000)
    return '\n'.join(f'{i.address:08x} {i.mnemonic:10} {i.op_str}' for i in decoder.disasm(raw[start-delta:end-delta],start))+'\n'


def cstring(kind,offset):
    raw=AP if kind=='ap' else CP
    return raw[offset:raw.index(b'\0',offset)].decode('ascii',errors='replace')
