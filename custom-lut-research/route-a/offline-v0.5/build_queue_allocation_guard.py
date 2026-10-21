"""Correct native CP queue allocation failure in the in-memory composition.

No camera I/O, complete image export, or release-state change.
"""
import json
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
import build_cp_handoff_placement as parent

HERE=parent.HERE
OUT=HERE/'lifecycle-dev/queue-allocation-build'
SITE=0xb832a6
DELTA=0x108000


def make():
    before,previous=parent.make()
    offset=SITE-DELTA
    old=bytes.fromhex('5cd1')
    new=bytes.fromhex('58d1')
    assert before[offset:offset+2]==old
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    for code,target in ((old,0xb83362),(new,0xb8335a)):
        ins=next(decoder.disasm(code,SITE))
        assert ins.mnemonic=='bne' and int(ins.op_str[1:],16)==target
    after=bytearray(before);after[offset:offset+2]=new
    reverse=bytearray(after);reverse[offset:offset+2]=old
    assert bytes(reverse)==before
    for p in previous['patches']:
        reverse[p['offset']:p['offset']+p['length']]=bytes.fromhex(p['before'])
    frozen=(HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    assert bytes(reverse)==frozen
    sha=parent.b.sha
    report={
        'status':'QUEUE_ALLOCATION_FAILURE_GUARD_NOT_READY_TO_FLASH',
        'camera_io':False,'full_image_written':False,
        'parent_cp_sha256':sha(before),'in_memory_cp_sha256':sha(after),
        'parent_recipe_sha256':sha((parent.OUT/'recipe.json').read_bytes()),
        'base_cp_sha256':sha(frozen),'inverse_to_parent_exact':True,
        'inverse_to_frozen_exact':True,
        'patches':[{'offset':offset,'length':2,'before':old.hex(),'after':new.hex(),
                    'purpose':'allocation failure takes native -20 return without freeing an unallocated message'}],
        'source_sha256':{__file__.split('/')[-1]:sha(open(__file__,'rb').read())}}
    OUT.mkdir(exist_ok=True)
    (OUT/'recipe.json').write_text(json.dumps(report,indent=2)+'\n')
    return bytes(after),report


if __name__=='__main__':
    _,r=make();print(json.dumps({k:r[k] for k in ('status','in_memory_cp_sha256')}))
