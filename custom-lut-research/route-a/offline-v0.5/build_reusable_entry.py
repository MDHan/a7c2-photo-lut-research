"""Offline CP composition with callback-finished photo tracking reuse.

This is not a shared LUT ownership solution or a flashable package.
"""
import hashlib
import json
from pathlib import Path
import struct
import build as b
import build_lifecycle_storage as storage

HERE=Path(__file__).resolve().parent
OUT=HERE/'lifecycle-dev/reuse-build'
ALIGN=lambda n:(n+3)&~3


def make():
    OUT.mkdir(exist_ok=True)
    cp=(HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    assert hashlib.sha256(cp).hexdigest()==storage.CP_HASH
    units={}
    for key, source in [('core','photo_lut_completion.c'),('bridge','vfx_callback_tag.S'),
                        ('storage','photo_lut_storage.S'),('guard','cp_result.S'),
                        ('retry','lut_idle_release.S')]:
        units[key]=b.compile_source(source,'armv7a-none-eabi',OUT)
    entry_size, callback_size=1600,256
    for attempt in range(8):
        addresses={'entry':b.CP_CODE};cursor=b.CP_CODE+ALIGN(entry_size)
        for key in ('guard','core','callbacks','bridge','storage','retry'):
            addresses[key]=cursor
            cursor+=ALIGN(callback_size if key=='callbacks' else len(units[key][0]))
        assert cursor<=0xc30000,hex(cursor)
        cs=units['core'][1]
        macros={name:addresses['core']+cs[fn] for name,fn in
                [('PLL_BEGIN','pll_begin'),('PLL_LOAD_COMPLETE','pll_load_complete'),
                 ('PLL_SUBMIT_COMPLETE','pll_submit_complete'),('PLL_FAULT','pll_fault'),
                 ('PLL_CALLBACK_CLAIM','pll_callback_claim'),('PLL_CALLBACK_FINISH','pll_callback_finish')]}
        def header():
            (OUT/'layout.h').write_text('/* Generated exact-build addresses. */\n'+''.join(
                f'#define {k} 0x{value:x}U\n' for k,value in macros.items()))
        header()
        callbacks=b.compile_source('photo_lut_notify.c','armv7a-none-eabi',OUT)
        ws=callbacks[1]
        macros.update(PHOTO_CALLBACK0=addresses['callbacks']+ws['photo_context0'],
                      PHOTO_CALLBACK1=addresses['callbacks']+ws['photo_context1'])
        header()
        entry=b.compile_source('photo_lut_reusable.c','armv7a-none-eabi',OUT)
        if len(entry[0])==entry_size and len(callbacks[0])==callback_size:break
        entry_size,callback_size=len(entry[0]),len(callbacks[0])
    else:raise AssertionError('layout did not stabilize')
    units['entry'],units['callbacks']=entry,callbacks
    for key,symbol,target,arm in [
        ('guard','cp_success_branch',0x48c790,False),('guard','cp_failure_branch',0x48c778,False),
        ('guard','cp_retry_branch',0x48c74e,False),('bridge','vfx_tag_capture_resume',0xbb353e,False),
        ('bridge','vfx_tag_deliver_resume',0xbb3610,False),('storage','photo_lut_storage_resume',0x60d35c,True),
        ('retry','lut_idle_release_resume',0x4e7f90,False)]:
        raw,symbols,_=units[key];at=symbols[symbol]
        raw[at:at+4]=(storage.arm_branch if arm else b.branch32)(addresses[key]+at,target)
    body=bytearray(cursor-b.CP_CODE)
    for key,(raw,_,_) in units.items():
        off=addresses[key]-b.CP_CODE;body[off:off+len(raw)]=raw
    result=bytearray(cp);patches=[]
    def patch(off,new,purpose):
        before=cp[off:off+len(new)];assert len(before)==len(new)
        if before==new:return
        assert all(off+len(new)<=p['offset'] or p['offset']+p['length']<=off for p in patches)
        result[off:off+len(new)]=new
        patches.append({'offset':off,'length':len(new),'before':before.hex(),
                        'after':bytes(new).hex(),'purpose':purpose})
    assert cp[0xbb353a-b.CP_DELTA:0xbb353e-b.CP_DELTA]==bytes.fromhex('d9f80880')
    assert cp[0xbb3608-b.CP_DELTA:0xbb3610-b.CP_DELTA]==bytes.fromhex('50f834100020c047')
    assert struct.unpack_from('<I',cp,0x2014c)[0]==storage.OLD_SIZE
    assert struct.unpack_from('<I',cp,0x60d338-b.CP_DELTA)[0]==0xe3053f5c
    assert cp[0x60d358-b.CP_DELTA:0x60d35c-b.CP_DELTA]==bytes.fromhex('00000ae3')
    assert cp[0x4e7f50-b.CP_DELTA:0x4e7f54-b.CP_DELTA]==bytes.fromhex('02201de0')
    patch(b.CP_CODE-b.CP_DELTA,body,'composed reusable photo entry and callbacks')
    patch(0x20128,struct.pack('<I',cursor-0x128000),'declared executable extent')
    patch(0x2014c,struct.pack('<I',storage.NEW_SIZE),'BSS extension')
    patch(0x60d338-b.CP_DELTA,struct.pack('<I',0xe3053f64),'BSS clear end')
    patch(0x60d358-b.CP_DELTA,storage.arm_branch(0x60d358,addresses['storage']),'cold-start initialization')
    patch(b.CP_ENTRY-b.CP_DELTA,b.branch32(b.CP_ENTRY,addresses['entry']+(entry[1]['photo_vfx_once']&~1),True),'photo entry')
    patch(b.CP_RESULT-b.CP_DELTA,b.branch32(b.CP_RESULT,addresses['guard'])+bytes.fromhex('00bf00bf'),'result guard')
    patch(0xbb353a-b.CP_DELTA,b.branch32(0xbb353a,addresses['bridge']+(units['bridge'][1]['vfx_tag_capture']&~1)),'snapshot callback tag')
    patch(0xbb3608-b.CP_DELTA,b.branch32(0xbb3608,addresses['bridge']+(units['bridge'][1]['vfx_tag_deliver']&~1))+bytes.fromhex('00bf00bf'),'deliver callback tag')
    patch(0x4e7f50-b.CP_DELTA,b.branch32(0x4e7f50,addresses['retry']),'check native release result')
    undo=bytearray(result)
    for p in patches:undo[p['offset']:p['offset']+p['length']]=bytes.fromhex(p['before'])
    assert bytes(undo)==cp
    report={'status':'EXPERIMENTAL_PHOTO_REUSE_NOT_READY_TO_FLASH','camera_io':False,
            'base_cp_sha256':storage.CP_HASH,'in_memory_cp_sha256':hashlib.sha256(result).hexdigest(),
            'full_image_written':False,'addresses':addresses,'payload_size':len(body),
            'symbols':{k:x[1] for k,x in units.items()},'sizes':{k:len(x[0]) for k,x in units.items()},
            'sources':[x[2] for x in units.values()],
            'layout_header_sha256':hashlib.sha256((OUT/'layout.h').read_bytes()).hexdigest(),
            'completion_header_sha256':hashlib.sha256((HERE/'photo_lut_completion.h').read_bytes()).hexdigest(),
            'builder_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'patches':patches,'inverse_exact':True}
    (OUT/'composed-payload.bin').write_bytes(body)
    (OUT/'recipe.json').write_text(json.dumps(report,indent=2)+'\n')
    return bytes(result),report


if __name__=='__main__':
    _,m=make();print(json.dumps({'sizes':m['sizes'],'total':m['payload_size'],
                                'status':m['status']}))
