"""Build a native-worker integration experiment at an emulator-only address.

The patched byte array cannot boot; only components/recipe are saved.
"""
import json
import build_queue_allocation_guard as parent

b=parent.parent.b
HERE=b.HERE
OUT=HERE/'lifecycle-dev/dma-worker-build'
CODE=0x80000
STATE=0x1b85ff8
GATE=0x1b85f68


def make():
    cp,previous=parent.make()
    OUT.mkdir(exist_ok=True)
    capture,cs,cc=b.compile_source('lut_dma_capture.c','armv7a-none-eabi',OUT)
    capture_address=CODE+cs['lut_dma_capture']
    (OUT/'layout.h').write_text('#define LUT_DMA_CAPTURE '+hex(capture_address)+'U\n')
    body,sy,bc=b.compile_source('lut_dma_worker.c','armv7a-none-eabi',OUT)
    pad=(-len(capture))%4
    body_address=CODE+len(capture)+pad
    payload=bytes(capture)+bytes(pad)+bytes(body)
    addresses={name:body_address+offset for name,offset in sy.items() if name}
    addresses['lut_dma_capture']=capture_address
    assert len(payload)<4096
    patched=bytearray(cp);patches=[]
    sites=[(pc,0xb83062,addresses['lut_dma_run']&~1) for pc in
           (0xb82d20,0xb82db2,0xb82df4,0xb82e52,0xb82ed6)]
    sites.append((0xb82c7c,0x53533c,addresses['lut_dma_dispatch']&~1))
    for pc,old,new in sites:
        offset=pc-b.CP_DELTA
        before=b.branch32(pc,old,True);after=b.branch32(pc,new,True)
        assert patched[offset:offset+4]==before
        patched[offset:offset+4]=after
        patches.append({'offset':offset,'length':4,'before':before.hex(),'after':after.hex()})
    undo=bytearray(patched)
    for p in patches:undo[p['offset']:p['offset']+4]=bytes.fromhex(p['before'])
    assert bytes(undo)==cp
    report={'status':'DMA_WORKER_EMULATOR_INTEGRATION_NOT_IN_FIRMWARE','camera_io':False,
            'full_image_written':False,'code_address_is_emulator_only':True,
            'cold_state_declaration_extended':False,'state_initialization_is_fixture':True,
            'code_address':CODE,'code_size':len(payload),'state':STATE,'state_bytes':4,
            'addresses':addresses,'patches':patches,'inverse_to_parent_exact':True,
            'parent_cp_sha256':b.sha(cp),'emulator_hooked_cp_sha256':b.sha(patched),
            'parent_recipe_sha256':b.sha((parent.OUT/'recipe.json').read_bytes()),
            'payload_sha256':b.sha(payload),'compiles':[cc,bc],
            'source_sha256':{name:b.sha((HERE/name).read_bytes()) for name in
                             ('build_lut_dma_worker.py','lut_dma_capture.c','lut_dma_worker.c',
                              'lifecycle-dev/dma-worker-build/layout.h')}}
    (OUT/'dma-worker.bin').write_bytes(payload)
    (OUT/'recipe.json').write_text(json.dumps(report,indent=2)+'\n')
    return bytes(patched),payload,report


if __name__=='__main__':
    _,_,r=make();print(json.dumps({'status':r['status'],'bytes':r['code_size']}))
