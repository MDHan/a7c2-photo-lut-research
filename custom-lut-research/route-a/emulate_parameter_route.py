"""Offline AP/CP LUT-parameter experiments; never writes a firmware file.

The optional counterfactual changes one instruction only inside Unicorn RAM.
No actual menu, transport, capture scheduler, image pixels or ISP are modeled.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as a64, arm_const as arm

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import binary_queries as q

AP_SHA='1aaeb8fbe0297950cab454d498d1a5ba874f91542aa2737aae27a73971e324d7'
CP_SHA='60a9de1a0636c7f6b5b98607a4d25eeb48634e25294f632743a6d256e583b370'
AP_ENTRY=0x352c5dc
AP_GATE=0x352c62c
AP_GATE_TARGET=0x352c684
CP_ENTRY=0x8db56e
GLOBAL=0x165a720
RAM,STACK,STOP=0x3000000,0x3100000,0x3200000
MSG,CONTEXT,OWNER=RAM,RAM+0x1000,RAM+0x2000


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def put32(uc,address,value):
    uc.mem_write(address,struct.pack('<I',value))


def execute(uc,start,allowed,*,thumb=False):
    count=0
    returned=False

    def instruction(emu,address,size,_):
        nonlocal count,returned
        if address==STOP:
            returned=True
            emu.emu_stop()
            return
        if not any(a<=address<b for a,b in allowed):
            raise RuntimeError(f'Unexpected external instruction: {address:#x}')
        count+=1

    def write(emu,access,address,size,value,_):
        if not (RAM<=address and address+size<=RAM+0x10000 or
                STACK<=address and address+size<=STACK+0x10000 or
                GLOBAL<=address and address+size<=GLOBAL+0xc00):
            raise RuntimeError(f'Unexpected native write: {address:#x}')

    uc.hook_add(UC_HOOK_CODE,instruction)
    uc.hook_add(UC_HOOK_MEM_WRITE,write)
    uc.emu_start(start|int(thumb),STOP,count=10000)
    pc=uc.reg_read(arm.UC_ARM_REG_PC if thumb else a64.UC_ARM64_REG_PC)
    if not returned and pc!=STOP:
        raise AssertionError('The native function did not return')
    return count


def ap_message(args,*,counterfactual=False):
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for page in (0x352c000,0x4c7d000):
        uc.mem_map(page,0x1000)
        uc.mem_write(page,q.AP[page:page+0x1000])
    for base in (RAM,STACK):
        uc.mem_map(base,0x10000)
    uc.mem_map(STOP,0x1000)
    if counterfactual:
        # Deliberately bypass the still-mode fallback in EMULATOR MEMORY ONLY.
        branch=0x14000000|((AP_GATE_TARGET-AP_GATE)//4)
        uc.mem_write(AP_GATE,struct.pack('<I',branch))
    for i,value in enumerate(args[:8]):
        uc.reg_write(getattr(a64,f'UC_ARM64_REG_X{i}'),value)
    sp=STACK+0xff00
    uc.reg_write(a64.UC_ARM64_REG_SP,sp)
    uc.reg_write(a64.UC_ARM64_REG_LR,STOP)
    uc.mem_write(sp,struct.pack('<QQ',args[8],MSG))
    uc.mem_write(MSG,b'\xa5'*64)
    count=execute(uc,AP_ENTRY,[(AP_ENTRY,0x352c790)])
    if uc.reg_read(a64.UC_ARM64_REG_SP)!=sp:
        raise AssertionError('AP stack differs')
    raw=bytes(uc.mem_read(MSG,64))
    if raw[:8]!=b'\xa5'*8 or raw[13:]!=b'\xa5'*51:
        raise AssertionError('AP wrote outside the five message fields')
    return raw[8:13],count


def reference(args,*,counterfactual=False):
    lut,exists,log,input_gamut,gamut,pp,mode,cinematic,look=args
    base={0:9,1:7,2:8}.get(lut,10 if exists==1 else 0)
    if mode==0 and not counterfactual:
        base,shooting=11,3
    elif log==0:
        if cinematic==0:
            enabled=6<=look<=21
        else:
            enabled=12<=pp<=15
        if enabled:
            shooting=0
        else:
            base,shooting=11,3
    elif log==1:
        shooting=2
    elif log in (2,3):
        shooting=1
    else:
        raise ValueError('Only known log values are modeled')
    return bytes([base,shooting,int(input_gamut==1),int(gamut==0),0])


def cp_machine():
    uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    uc.mem_map(0x100000,0x2000000)
    uc.mem_write(0x108000,q.CP)
    for base in (RAM,STACK):
        uc.mem_map(base,0x10000)
    uc.mem_map(STOP,0x1000)
    uc.reg_write(arm.UC_ARM_REG_SP,STACK+0xff00)
    uc.reg_write(arm.UC_ARM_REG_LR,STOP|1)
    return uc


def cp_receive(fields):
    uc=cp_machine()
    uc.mem_write(MSG+8,fields)
    put32(uc,GLOBAL+0xb04,0x55)
    put32(uc,GLOBAL+0x684,17)
    uc.reg_write(arm.UC_ARM_REG_R0,MSG)
    execute(uc,CP_ENTRY,[(CP_ENTRY,0x8db5d4)],thumb=True)
    offsets=(0xaf8,0xafc,0xb00,0xb04,0xb08)
    values=[struct.unpack('<I',uc.mem_read(GLOBAL+off,4))[0] for off in offsets]
    expected=list(fields)
    if fields[1]==3:
        expected[3]=0x55
    if values!=expected or struct.unpack('<I',uc.mem_read(GLOBAL+0x684,4))[0]!=18:
        raise AssertionError('CP receive model differs')
    # Check the subsequent unmodified context-copy routine separately.
    put32(uc,OWNER,GLOBAL)
    uc.reg_write(arm.UC_ARM_REG_R0,OWNER)
    uc.reg_write(arm.UC_ARM_REG_R1,CONTEXT)
    uc.reg_write(arm.UC_ARM_REG_LR,STOP|1)
    # A fresh hook would reject this function under the previous allowed range,
    # so use an independent machine for the second native experiment.
    copy=cp_machine()
    put32(copy,OWNER,GLOBAL)
    for off,value in zip(offsets,values):
        put32(copy,GLOBAL+off,value)
    copy.reg_write(arm.UC_ARM_REG_R0,OWNER)
    copy.reg_write(arm.UC_ARM_REG_R1,CONTEXT)
    execute(copy,0x332e78,[(0x332e78,0x332f04)],thumb=True)
    copied=[struct.unpack('<I',copy.mem_read(CONTEXT+off,4))[0] for off in (0x778,0x780,0x784,0x77c,0x788)]
    if copied!=values:
        raise AssertionError('CP context copy differs')
    return values,copied


def cp_select(base,shooting,size):
    uc=cp_machine()
    for reg,value in ((arm.UC_ARM_REG_R0,base),(arm.UC_ARM_REG_R1,shooting),(arm.UC_ARM_REG_R2,size)):
        uc.reg_write(reg,value)
    execute(uc,0xb31aac,[(0xb31aac,0xb31ac4)],thumb=True)
    result=uc.reg_read(arm.UC_ARM_REG_R0)
    expected=11 if shooting==3 else (0 if base==10 and size==0 else base)
    if result!=expected:
        raise AssertionError('CP LUT selector differs')
    return result


def cp_descriptor(base,shooting,input_gamut,color_gamut,reg_size):
    uc=cp_machine()
    for reg,value in ((arm.UC_ARM_REG_R0,shooting),(arm.UC_ARM_REG_R1,base),
                      (arm.UC_ARM_REG_R2,color_gamut),(arm.UC_ARM_REG_R3,input_gamut)):
        uc.reg_write(reg,value)
    uc.mem_write(STACK+0xff00,struct.pack('<II',0,reg_size))
    execute(uc,0x4e8a5c,[(0x4e8a5c,0x4e8b22)],thumb=True)
    return uc.reg_read(arm.UC_ARM_REG_R0)


def run():
    if digest(q.AP)!=AP_SHA or digest(q.CP)!=CP_SHA:
        raise ValueError('The current exact FL23 AP/CP pair is required')
    cases=[]
    for lut in range(3,19):
        for pp in range(12,16):
            for mode in (0,1):
                for exists in (0,1):
                    cases.append((lut,exists,0,0,0,pp,mode,1,0))
    for log in range(4):
        for mode in (0,1):
            for input_gamut in (0,1):
                for gamut in (0,1):
                    cases.append((3,1,log,input_gamut,gamut,12,mode,1,0))
    for pp in (0,1,11):
        for mode in (0,1):
            cases.append((3,1,0,0,0,pp,mode,1,0))
    for lut in (0,1,2):
        for mode in (0,1):
            cases.append((lut,1,0,0,0,12,mode,1,0))
    for look in (0,5,6,21,22):
        for mode in (0,1):
            cases.append((3,1,0,0,0,12,mode,0,look))
    for args in cases:
        actual,_=ap_message(args)
        if actual!=reference(args):
            raise AssertionError(f'AP reference disagreement: {args}, {list(actual)}')
    interventions=[]
    for lut in range(3,19):
        for pp in range(12,16):
            args=(lut,1,0,0,0,pp,0,1,0)
            actual,_=ap_message(args,counterfactual=True)
            if actual!=reference(args,counterfactual=True) or actual[:2]!=bytes([10,0]):
                raise AssertionError('In-RAM counterfactual differs')
            interventions.append({'lut':lut,'pp':pp,'message_fields':list(actual)})
    downstream=[]
    for fields in (bytes([11,3,0,1,0]),bytes([10,0,0,1,0]),bytes([10,0,1,0,0])):
        received,copied=cp_receive(fields)
        for size in (0,256):
            selected=cp_select(received[0],received[1],size)
            descriptor=cp_descriptor(selected,received[1],received[2],received[3],256)
            downstream.append({'message':list(fields),'cp_saved_fields':received,'cp_context_fields':copied,
                               'synthetic_lut_size':size,'cp_effective_base':selected,
                               'native_mlut_descriptor':descriptor})
    for base in range(12):
        for shooting in range(4):
            for size in (0,256):
                cp_select(base,shooting,size)
    return {'status':'OFFLINE_NATIVE_LUT_PARAMETER_ROUTE_PASSED','camera_io':False,
            'source_ap_sha256':AP_SHA,'source_cp_sha256':CP_SHA,
            'ap_original_cases':len(cases),'ap_in_ram_counterfactual_cases':len(interventions),
            'cp_selector_cases':96,'downstream_examples':downstream,
            'gate':{'va_and_file_offset':hex(AP_GATE),'native_bytes':q.AP[AP_GATE:AP_GATE+4].hex(),
                    'original':'cbnz w6, 0x352c684; zero general mode instead reaches base11/mode3 fallback',
                    'counterfactual':'Unconditional branch in emulator RAM only; no patched firmware is emitted'},
            'ap_argument_names':['selected_lut','user_lut_exists','log_shooting','input_gamut','color_gamut',
                                 'picture_profile','general_shooting_mode','cinematic_mode','cinematic_look'],
            'mode_label_evidence':'Native enum-name table lists STILL then MOVIE; zero/nonzero routing independently exercised',
            'not_validated':['Actual menu eligibility and settings persistence','Actual AP/CP transport',
                             'Full still/capture scheduler','ISP and DMA resources','Image pixels, JPEG/HEIF and preview',
                             'Exposure/gamma behavior and color accuracy','Safety of a whole firmware patch'],
            'source_files_written':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=run()
    with args.output.open('x',encoding='utf-8') as stream:
        json.dump(report,stream,indent=2)
        stream.write('\n')
    print(json.dumps({k:report[k] for k in ('status','ap_original_cases','ap_in_ram_counterfactual_cases','cp_selector_cases','camera_io')}))
