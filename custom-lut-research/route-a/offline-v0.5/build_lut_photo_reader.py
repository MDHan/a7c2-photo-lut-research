"""Photo snapshot parent lease plus native queued-message child leases."""
import json
import build_lut_dma_placement as base
OUT=base.HERE/'lifecycle-dev/photo-reader-build'


def make():
    cp,code,r=base.make(OUT,'lut_photo_reader_worker.c','lut_photo_reader_storage.S',True,True)
    r['status']='PHOTO_SNAPSHOT_READER_GUARD_NOT_READY_TO_FLASH'
    r['producer_snapshot_protection_connected']='custom_photo_entry_only'
    r['source_sha256'].update({name:base.b.sha((base.HERE/name).read_bytes()) for name in
                              ('build_lut_photo_reader.py','lut_reader_worker.c','lut_photo_snapshot.h')})
    (OUT/'recipe.json').write_text(json.dumps(r,indent=2)+'\n')
    return cp,code,r


if __name__=='__main__':
    _,_,r=make();print(json.dumps({k:r[k] for k in ('status','code_size','in_memory_cp_sha256')}))
