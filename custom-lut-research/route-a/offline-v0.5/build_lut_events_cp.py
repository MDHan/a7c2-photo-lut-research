"""Place CP publication/ingress and restore packed native parameters at boot.

Uses declared segment tails and explicitly reserves the final allocator gap. Native
parameter addresses and all 3872 runtime bytes remain unchanged after restore.
"""
import json
import struct
from pathlib import Path
import build_lut_cp_publication as publication

b=publication.base.b
parent=publication.parent
OUT=b.HERE/'lifecycle-dev/events-cp-build'
CODE=0x1b87000
PARAMETERS=0x1208b80
PARAMETER_BYTES=3872
SCRATCH=0x1b86000
STATE=SCRATCH+PARAMETER_BYTES
END=0x1b87000
HOOK=0x4b3b2c


def pack(data):
    output=bytearray();literal=bytearray();at=0
    while at<len(data):
        best=0;distance=0
        for back in range(max(0,at-4095),at):
            if data[back]!=data[at]:continue
            count=1
            while count<130 and at+count<len(data) and data[back+count]==data[at+count]:count+=1
            if count>best:best=count;distance=at-back
        if best>=4:
            if literal:output.append(len(literal)-1);output+=literal;literal.clear()
            output.append(128+best-3);output+=distance.to_bytes(2,'little');at+=best
        else:
            literal.append(data[at]);at+=1
            if len(literal)==128:output.append(127);output+=literal;literal.clear()
    if literal:output.append(len(literal)-1);output+=literal
    return bytes(output)


def unpack(data,count):
    output=bytearray();at=0
    while at<len(data):
        command=data[at];at+=1
        if command<128:
            n=command+1;assert at+n<=len(data);output+=data[at:at+n];at+=n
        else:
            n=(command&127)+3;assert at+2<=len(data)
            distance=int.from_bytes(data[at:at+2],'little');at+=2
            assert 0<distance<=len(output)
            for _ in range(n):output.append(output[-distance])
        assert len(output)<=count*4
    assert len(output)==count*4
    return bytes(output)


def make():
    cp,payload,pr,pub,pubr=publication.make()
    OUT.mkdir(exist_ok=True)
    native=cp[PARAMETERS-b.CP_DELTA:PARAMETERS-b.CP_DELTA+PARAMETER_BYTES]
    frozen=(b.HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    assert native==frozen[PARAMETERS-b.CP_DELTA:PARAMETERS-b.CP_DELTA+PARAMETER_BYTES]
    packed=pack(native);assert unpack(packed,PARAMETER_BYTES//4)==native
    source=PARAMETERS+(len(packed)+3)//4*4
    assert STATE+116<=END and len(payload)%4==0
    core=json.loads((publication.base.parent.parent.OUT/'recipe.json').read_text())
    (OUT/'publication-layout.h').write_text(''.join(f'#define {name} {hex(core["core_addresses"][symbol])}U\n' for name,symbol in [('CP_REQUEST','lh_cp_request'),('CP_PUBLISHED','lh_cp_published'),('CP_OPEN','lh_cp_open')]))
    pub,pub_symbols,pub_compile=b.compile_source('lut_cp_upload_publication.c','armv7a-none-eabi',OUT)
    pubr={'symbols':pub_symbols}
    definitions={
        'CP_STATE':core['state'],'CP_PUBLICATION_STATE':STATE,
        'LUT_PACKED_PARAMETERS':PARAMETERS,'LUT_NATIVE_PARAMETERS':PARAMETERS,
        'LUT_PARAMETER_SCRATCH':SCRATCH,'LUT_PARAMETER_WORDS':PARAMETER_BYTES//4,
        'LUT_CODE_SOURCE_LOW':source&65535,
        'LUT_DMA_CAPTURE':pr['addresses']['lut_dma_capture'],
        'LUT_REUSABLE_PHOTO_ENTRY':0xc2f491,
        'CP_INGRESS_ENTRY':CODE+0xfff,
        'LUT_NATIVE_APPLY_ORIGINAL':CODE+0xf01,'LUT_NATIVE_LOAD_ORIGINAL':CODE+0xf11,
        'LUT_NATIVE_ART_ORIGINAL':CODE+0xf21,'LUT_NATIVE_QUEUE_ORIGINAL':CODE+0xf31,
        'LUT_NATIVE_ART_QUEUE_ORIGINAL':CODE+0xf41,'LUT_NATIVE_PUBLISH_ORIGINAL':CODE+0xf51,
    }
    definitions.update({name:core['core_addresses'][symbol] for name,symbol in (
        ('CP_READER_BEGIN','lh_cp_reader_begin'),('CP_READER_END','lh_cp_reader_end'),
        ('CP_READER_FAULT','lh_cp_reader_fault'))})
    def layout():
        (OUT/'layout.h').write_text(''.join(f'#define {k} {hex(v)}\n' for k,v in definitions.items()))
    layout()
    capture,csy,cc=b.compile_source('lut_dma_capture.c','armv7a-none-eabi',OUT)
    definitions['LUT_DMA_CAPTURE']=CODE+csy['lut_dma_capture']
    layout()
    prefix=capture+bytes((-len(capture))%4)
    body,bsy,bc=b.compile_source('lut_events_reader_worker.c','armv7a-none-eabi',OUT)
    prefix_size=len(prefix)
    first_size=prefix_size+len(body)
    first_size=(first_size+3)//4*4
    pub_address=CODE+first_size
    ingress_address=pub_address+(len(pub)+3)//4*4
    definitions.update(CP_PUBLICATION_ENTRY=pub_address+pubr['symbols']['lh_cp_receive_publication'],
                       CP_INGRESS_ENTRY=ingress_address|1)
    layout()
    body2,bsy2,bc=b.compile_source('lut_events_reader_worker.c','armv7a-none-eabi',OUT)
    assert len(body2)==len(body) and bsy2==bsy
    combined=prefix+body2;combined+=bytes((-len(combined))%4)
    assert len(combined)==first_size
    combined+=pub;combined+=bytes((-len(combined))%4)
    ingress,isy,ic=b.compile_source('lut_events_cp_ingress.c','armv7a-none-eabi',OUT)
    assert isy['lh_cp_ingress']==1
    combined+=ingress;combined+=bytes((-len(combined))%4)
    restore_address=CODE+len(combined)
    restore,rsy,rc=b.compile_source('lut_upload_restore.c','armv7a-none-eabi',OUT)
    combined+=restore;combined+=bytes((-len(combined))%4)
    trampoline_address=CODE+len(combined)
    trampolines,tsy,tc=b.compile_source('lut_events_trampolines.S','armv7a-none-eabi',OUT)
    combined+=trampolines
    for macro,symbol in [('APPLY','apply'),('LOAD','load'),('ART','art'),('QUEUE','queue'),('ART_QUEUE','art_queue'),('PUBLISH','publish')]:
        definitions['LUT_NATIVE_'+macro+'_ORIGINAL']=trampoline_address+tsy['lut_original_'+symbol]
    layout()
    final_body,final_symbols,bc=b.compile_source('lut_events_reader_worker.c','armv7a-none-eabi',OUT)
    assert len(final_body)==len(body2) and final_symbols==bsy2
    combined[len(prefix):len(prefix)+len(final_body)]=final_body
    assert source+len(combined)<=0x120a000,(len(packed),len(combined),hex(source+len(combined)))
    assert len(combined)<=4096
    definitions.update(LUT_PARAMETER_RESTORE_ENTRY=restore_address+rsy['lut_restore_parameters'],
                       LUT_DMA_WORDS=len(combined)//4)
    layout()
    init,ss,sc=b.compile_source('lut_events_cp_storage.S','armv7a-none-eabi',OUT)
    assert len(init)==pr['copy_init_size']==132
    changed=bytearray(cp);patches=[]
    def patch(va,after,purpose,offset=False):
        at=va if offset else va-b.CP_DELTA
        before=bytes(changed[at:at+len(after)])
        assert len(before)==len(after)
        assert all(at+len(after)<=x['offset'] or x['offset']+x['length']<=at for x in patches)
        changed[at:at+len(after)]=after
        patches.append({'offset':at,'length':len(after),'before':before.hex(),'after':after.hex(),'purpose':purpose})
    stream=packed+bytes(source-PARAMETERS-len(packed))+combined
    # Erase old source bytes in the same original initialized-data tail.
    stop=max(PARAMETERS+len(stream),pr['source']+pr['code_size'])
    patch(PARAMETERS,stream+bytes(stop-PARAMETERS-len(stream)),'packed exact native parameters followed by runtime code')
    patch(pr['copy_init'],init,'copy new source, make code RX, restore native parameters before publication')
    assert cp[HOOK-b.CP_DELTA:HOOK-b.CP_DELTA+4]==b.branch32(HOOK,0x35cf70,True)
    addresses={name:CODE+prefix_size+off for name,off in bsy.items() if name}
    addresses['lut_dma_capture']=CODE+csy['lut_dma_capture']
    veneer=lambda target:bytes.fromhex('dff800f0')+struct.pack('<I',target)
    patch(pr['dispatch_veneer'],veneer(addresses['lut_dma_dispatch']),'shared LR-dispatched IPC and reader veneer')
    patch(pr['run_veneer'],veneer(addresses['lut_dma_run']),'native DMA wait target in combined payload')
    for site in (0x4c2eae,0xb2b4d4,0xb2b596,0xb2ba0e):
        patch(site,b.branch32(site,0x4e876c,True),'central function entry supersedes cached callsite guard')
    for entry,symbol in [(0x4e876c,'lut_all_context'),(0x54e15c,'lut_all_load'),(0x54e398,'lut_all_art'),(0xb799de,'lut_all_queue'),(0xb79ab4,'lut_all_art_queue'),(0x35c54c,'lut_all_publish')]:
        jump=veneer(addresses[symbol]) if entry%4==0 else bytes.fromhex('dff804f000bf')+struct.pack('<I',addresses[symbol])
        # At a halfword-aligned entry, aligned PC is entry+2; +4 reaches
        # the word-aligned literal at entry+6. Displace ten complete bytes.
        patch(entry,jump,'guard every direct and indirect entry before source access')
    patch(HOOK,b.branch32(HOOK,pr['dispatch_veneer'],True),'native receive worker to placed ingress through shared veneer')
    assert cp[0x61a08c-b.CP_DELTA:0x61a090-b.CP_DELTA]==bytes.fromhex('580000eb')
    patch(0x61a08c,struct.pack('<I',0xe320f000),'reserve exact final 4096-byte allocator gap for runtime code')
    patch(0x20140,struct.pack('<I',source+len(combined)-0x10c7000),'declared RW initialized extent',True)
    assert struct.unpack_from('<I',cp,0x2014c)[0]==END-0x120a000
    undo=bytearray(changed)
    for p in patches:undo[p['offset']:p['offset']+p['length']]=bytes.fromhex(p['before'])
    assert bytes(undo)==cp
    r={
        'status':'UPLOAD_CP_SESSION_CLEAR_AND_INGRESS_PENDING_VERIFICATION','camera_io':False,'full_image_written':False,
        'parent_cp_sha256':b.sha(cp),'in_memory_cp_sha256':b.sha(changed),'patches':patches,
        'code_address':CODE,'code_size':len(combined),'source':source,'bss_end':END,
        'allocator_reserved_gap':[CODE,4096],'allocator_skip_call':0x61a08c,
        'publication_address':pub_address,'publication_state':STATE,'publication_state_bytes':116,
        'ingress_address':ingress_address+isy['lh_cp_ingress'],
        'restore_address':restore_address+rsy['lut_restore_parameters'],
        'restore_code_start':restore_address,'restore_code_size':len(restore),
        'native_parameters':PARAMETERS,'native_parameter_bytes':PARAMETER_BYTES,
        'native_parameter_sha256':b.sha(native),'packed_bytes':len(packed),'packed_sha256':b.sha(packed),
        'scratch':SCRATCH,'payload_sha256':b.sha(combined),
        'copy_init':pr['copy_init'],'copy_init_size':len(init),'copy_symbols':ss,
        'run_veneer':pr['run_veneer'],'dispatch_veneer':pr['dispatch_veneer'],
        'addresses':addresses,'compiles':[cc,bc,pub_compile,ic,rc,tc,sc],
        'publication_symbols':pub_symbols,'publication_size':len(pub),
        'parent_recipe_sha256':b.sha((parent.OUT/'recipe.json').read_bytes()),
        'publication_recipe_sha256':b.sha((publication.OUT/'component.json').read_bytes()),
        'inverse_to_parent_exact':True,
        'source_sha256':{n:b.sha((b.HERE/n).read_bytes()) for n in (
            Path(__file__).name,'lut_events_trampolines.S','lut_all_readers.h','lut_events_native_snapshot.h','lut_events_cp_ingress.c','lut_cp_ingress.c',
            'lut_upload_restore.c','lut_events_cp_storage.S','lut_events_reader_worker.c',
            'lut_reader_worker.c','lut_dma_capture.c','lut_dma_worker.c',
            'lut_photo_snapshot.h','lut_native_snapshot.h','lut_cp_publication.c','lut_cp_publication.h',
            'lut_handoff_cp.h','lut_handoff_ap.h','lut_cp_upload_publication.c',
            str((OUT/'publication-layout.h').relative_to(b.HERE)),str((OUT/'layout.h').relative_to(b.HERE)))},
    }
    (OUT/'runtime-code.bin').write_bytes(combined)
    (OUT/'parameters-packed.bin').write_bytes(packed)
    (OUT/'cold-copy.bin').write_bytes(init)
    (OUT/'recipe.json').write_text(json.dumps(r,indent=2)+'\n')
    return bytes(changed),bytes(combined),r


if __name__=='__main__':
    *_,r=make();print(json.dumps({k:r[k] for k in ('status','code_size','packed_bytes','source','bss_end')}))
