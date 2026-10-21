"""Place DMA bridges in a reserved BSS code page copied at cold startup.

Only components and reversible recipe are saved; no camera or full image.
"""
import json
import struct
import build_lut_dma_worker as component

b=component.b
parent=component.parent
HERE=b.HERE
OUT=HERE/'lifecycle-dev/dma-placement-build'
CODE=0x1b86000
SOURCE=0x1209aa0
STATE=component.STATE
END=CODE+4096
TEXT_VENEER=0xc2fff8
INIT=0x10c6f74


def make(out=OUT,worker_source='lut_dma_placed_worker.c',storage_source='lut_dma_storage.S',queue_hooks=False,photo_hook=False,native_hooks=False):
    cp,pr=parent.make()
    placement=json.loads((parent.parent.OUT/'recipe.json').read_text())
    out.mkdir(exist_ok=True)
    capture,cs,cc=b.compile_source('lut_dma_capture.c','armv7a-none-eabi',out)
    capture_address=CODE+cs['lut_dma_capture']
    layout=out/'layout.h'
    layout.write_text('#define LUT_DMA_CAPTURE '+hex(capture_address)+'U\n')
    if queue_hooks:
        layout.write_text(layout.read_text()+''.join('#define '+name+' '+hex(placement['core_addresses'][symbol])+'U\n'
            for name,symbol in [('CP_READER_BEGIN','lh_cp_reader_begin'),('CP_READER_END','lh_cp_reader_end'),
                                ('CP_READER_FAULT','lh_cp_reader_fault')]))
    if photo_hook:
        assert queue_hooks
        layout.write_text(layout.read_text()+'#define LUT_REUSABLE_PHOTO_ENTRY 0xc2f491U\n')
    body,sy,bc=b.compile_source(worker_source,'armv7a-none-eabi',out)
    payload=bytes(capture)+bytes((-len(capture))%4)+bytes(body)
    body_address=CODE+(len(capture)+3)//4*4
    addresses={name:body_address+off for name,off in sy.items() if name}
    addresses['lut_dma_capture']=capture_address
    payload+=bytes((-len(payload))%4)
    assert len(payload)<=0x120a000-SOURCE
    layout.write_text(layout.read_text()+'#define LUT_DMA_WORDS '+str(len(payload)//4)+'\n')
    init,ss,sc=b.compile_source(storage_source,'armv7a-none-eabi',out)
    assert len(init)%4==0 and INIT+len(init)+8<=0x10c7000,len(init)
    ro_veneer=INIT+len(init)
    init[ss['dma_storage_resume']:ss['dma_storage_resume']+4]=parent.parent.storage.arm_branch(
        INIT+ss['dma_storage_resume'],0x60d35c)
    veneer=lambda target:bytes.fromhex('dff800f0')+struct.pack('<I',target)
    changed=bytearray(cp);patches=[]
    def patch(va,after,reason,file_offset=False):
        at=va if file_offset else va-b.CP_DELTA
        before=bytes(changed[at:at+len(after)])
        assert len(before)==len(after)
        for old in patches:assert at+len(after)<=old['offset'] or old['offset']+old['length']<=at
        changed[at:at+len(after)]=after
        patches.append({'offset':at,'length':len(after),'before':before.hex(),'after':after.hex(),'purpose':reason})
    assert cp[SOURCE-b.CP_DELTA:SOURCE-b.CP_DELTA+len(payload)]==bytes(len(payload))
    assert cp[INIT-b.CP_DELTA:ro_veneer+8-b.CP_DELTA]==bytes(len(init)+8)
    assert cp[TEXT_VENEER-b.CP_DELTA:TEXT_VENEER+8-b.CP_DELTA]==bytes(8)
    patch(SOURCE,payload,'declared RW source bytes, never executed here')
    patch(INIT,bytes(init)+veneer(addresses['lut_dma_run']),'cold copier and absolute Thumb run veneer')
    patch(TEXT_VENEER,veneer(addresses['lut_dma_dispatch']),'absolute Thumb dispatch veneer')
    first=placement['storage_init']+placement['storage_symbols']['handoff_storage_resume']
    assert cp[first-b.CP_DELTA:first-b.CP_DELTA+4]==parent.parent.storage.arm_branch(first,0x60d35c)
    patch(first,parent.parent.storage.arm_branch(first,INIT),'continue cold setup before native publication')
    patch(0x60d338,struct.pack('<I',0xe3073000),'native clear end becomes 0x1b87000')
    for offset,value in [(0x20128,TEXT_VENEER+8-0x128000),(0x20134,ro_veneer+8-0xc30000),
                         (0x20140,SOURCE+len(payload)-0x10c7000),(0x2014c,END-parent.parent.storage.BSS_START)]:
        patch(offset,struct.pack('<I',value),'declared extent',True)
    for pc in (0xb82d20,0xb82db2,0xb82df4,0xb82e52,0xb82ed6):
        assert cp[pc-b.CP_DELTA:pc-b.CP_DELTA+4]==b.branch32(pc,0xb83062,True)
        patch(pc,b.branch32(pc,ro_veneer,True),'checked native DMA wait via veneer')
    assert cp[0xb82c7c-b.CP_DELTA:0xb82c80-b.CP_DELTA]==b.branch32(0xb82c7c,0x53533c,True)
    patch(0xb82c7c,b.branch32(0xb82c7c,TEXT_VENEER,True),'fault-gated worker dispatch via veneer')
    if queue_hooks:
        for pc in (0xb79a6a,0xb79b3a):
            assert cp[pc-b.CP_DELTA:pc-b.CP_DELTA+4]==b.branch32(pc,0xb83282,True)
            patch(pc,b.branch32(pc,TEXT_VENEER,True),'per-message read lease before native enqueue')
    if photo_hook:
        pc=0x48c740
        assert cp[pc-b.CP_DELTA:pc-b.CP_DELTA+4]==b.branch32(pc,0xc2f490,True)
        patch(pc,b.branch32(pc,TEXT_VENEER,True),'parent photo read lease before shared descriptor snapshot')
    if native_hooks:
        assert queue_hooks and photo_hook
        for pc in (0x4c2eae,0xb2b4d4,0xb2b596,0xb2ba0e):
            assert cp[pc-b.CP_DELTA:pc-b.CP_DELTA+4]==b.branch32(pc,0x4e876c,True)
            patch(pc,b.branch32(pc,TEXT_VENEER,True),'validate cached native LUT descriptor under parent read lease')
    undo=bytearray(changed)
    for p in patches:undo[p['offset']:p['offset']+p['length']]=bytes.fromhex(p['before'])
    assert bytes(undo)==cp
    for recipe in (pr,placement):
        for p in recipe['patches']:undo[p['offset']:p['offset']+p['length']]=bytes.fromhex(p['before'])
    assert bytes(undo)==(HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    report={'status':'COLD_COPIED_DMA_CODE_PLACEMENT_NOT_READY_TO_FLASH','camera_io':False,
            'full_image_written':False,'source':SOURCE,'code_address':CODE,'code_size':len(payload),
            'state':STATE,'state_bytes':4,'bss_end':END,'addresses':addresses,
            'copy_init':INIT,'copy_init_size':len(init),'copy_symbols':ss,
            'run_veneer':ro_veneer,'dispatch_veneer':TEXT_VENEER,'patches':patches,
            'payload_sha256':b.sha(payload),'parent_cp_sha256':b.sha(cp),'in_memory_cp_sha256':b.sha(changed),
            'parent_recipe_sha256':b.sha((parent.OUT/'recipe.json').read_bytes()),
            'cp_placement_recipe_sha256':b.sha((parent.parent.OUT/'recipe.json').read_bytes()),
            'inverse_to_parent_exact':True,'inverse_to_frozen_exact':True,'compiles':[cc,bc,sc],
            'native_queue_reader_hooks':queue_hooks,
            'photo_snapshot_reader_hook':photo_hook,
            'native_cached_reader_hooks':native_hooks,
            'source_sha256':{name:b.sha((HERE/name).read_bytes()) for name in
                             dict.fromkeys(('build_lut_dma_placement.py','lut_dma_capture.c','lut_dma_worker.c',
                              worker_source,storage_source,'lut_dma_storage.S','lut_handoff_cp.h','lut_handoff_ap.h',
                              str(layout.relative_to(HERE))))}}
    (out/'runtime-code.bin').write_bytes(payload)
    (out/'cold-copy.bin').write_bytes(init)
    (out/'recipe.json').write_text(json.dumps(report,indent=2)+'\n')
    return bytes(changed),payload,report


if __name__=='__main__':
    _,_,r=make();print(json.dumps({k:r[k] for k in ('status','code_size','copy_init_size','run_veneer','in_memory_cp_sha256')}))
