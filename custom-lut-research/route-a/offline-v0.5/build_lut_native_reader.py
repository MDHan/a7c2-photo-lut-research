"""Guard four native cached-context consumers in the photo/queue composition."""
import json
import build_lut_dma_placement as base
OUT=base.HERE/'lifecycle-dev/native-reader-build'


def make():
    cp,code,r=base.make(OUT,'lut_native_reader_worker.c','lut_native_reader_storage.S',True,True,True)
    r['status']='NATIVE_CACHED_LUT_REVALIDATION_NOT_READY_TO_FLASH'
    r['producer_snapshot_protection_connected']='photo_entry_and_four_native_cached_context_consumers'
    r['source_sha256'].update({name:base.b.sha((base.HERE/name).read_bytes()) for name in
                              ('build_lut_native_reader.py','lut_reader_worker.c','lut_photo_snapshot.h','lut_native_snapshot.h')})
    (OUT/'recipe.json').write_text(json.dumps(r,indent=2)+'\n')
    return cp,code,r


if __name__=='__main__':
    _,_,r=make();print(json.dumps({k:r[k] for k in ('status','code_size','in_memory_cp_sha256')}))
