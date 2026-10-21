"""Actual CP per-message read leases; producer snapshot protection is pending."""
import json
import build_lut_dma_placement as base
OUT=base.HERE/'lifecycle-dev/reader-placement-build'


def make():
    cp,code,r=base.make(OUT,'lut_reader_worker.c','lut_reader_storage.S',True)
    r['status']='NATIVE_QUEUE_READER_LEASES_NOT_READY_TO_FLASH'
    r['producer_snapshot_protection_connected']=False
    r['source_sha256']['build_lut_reader_placement.py']=base.b.sha((base.HERE/'build_lut_reader_placement.py').read_bytes())
    (OUT/'recipe.json').write_text(json.dumps(r,indent=2)+'\n')
    return cp,code,r


if __name__=='__main__':
    _,_,r=make();print(json.dumps({k:r[k] for k in ('status','code_size','in_memory_cp_sha256')}))
