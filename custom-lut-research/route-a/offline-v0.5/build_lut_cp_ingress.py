"""Native IPC hook composition at explicit emulator code/state addresses.

Not a firmware export: formal placement and boot initialization remain pending.
"""
import json
from pathlib import Path
import build_lut_cp_publication as parent

b = parent.base.b
OUT = b.HERE / 'lifecycle-dev/cp-ingress-build'
PUBLICATION_CODE, INGRESS_CODE, PUBLICATION_STATE = 0x90000, 0xa0000, 0x300d000
HOOK = 0x4b3b2c


def make():
    cp, payload, pr, publication, pub = parent.make()
    core = json.loads((parent.base.parent.parent.OUT / 'recipe.json').read_text())
    OUT.mkdir(exist_ok=True)
    entry = PUBLICATION_CODE + pub['symbols']['lh_cp_receive_publication']
    (OUT / 'layout.h').write_text(
        f'#define CP_PUBLICATION_ENTRY {hex(entry | 1)}U\n'
        f'#define CP_STATE {hex(core["state"])}U\n'
        f'#define CP_PUBLICATION_STATE {hex(PUBLICATION_STATE)}U\n')
    code, symbols, compile = b.compile_source('lut_cp_ingress.c','armv7a-none-eabi',OUT)
    before = b.branch32(HOOK,0x35cf70,True)
    after = b.branch32(HOOK,(INGRESS_CODE+symbols['lh_cp_ingress']) & ~1,True)
    at = HOOK-b.CP_DELTA
    assert cp[at:at+4] == before
    patched = bytearray(cp); patched[at:at+4] = after
    undo = bytearray(patched); undo[at:at+4] = before
    assert undo == cp
    report = {
        'status':'CP_NATIVE_INGRESS_HOOK_EMULATOR_PLACEMENT', 'camera_io':False,
        'full_image_written':False, 'formal_code_and_state_placement':False,
        'code_bytes':len(code), 'symbols':symbols, 'compile':compile,
        'publication_code':PUBLICATION_CODE, 'ingress_code':INGRESS_CODE,
        'publication_state':PUBLICATION_STATE, 'cp_state':core['state'],
        'publication_sha256':b.sha(publication), 'ingress_sha256':b.sha(code),
        'parent_cp_sha256':b.sha(cp), 'in_memory_cp_sha256':b.sha(patched),
        'hook':{'address':HOOK,'before':before.hex(),'after':after.hex()},
        'inverse_to_parent_verified':True,
        'source_sha256':{n:b.sha((b.HERE/n).read_bytes()) for n in (
            Path(__file__).name,'lut_cp_ingress.c','lut_cp_publication.h',
            'lifecycle-dev/cp-ingress-build/layout.h')},
    }
    (OUT/'ingress.bin').write_bytes(code)
    (OUT/'component.json').write_text(json.dumps(report,indent=2)+'\n')
    return bytes(patched),payload,pr,publication,pub,bytes(code),report


if __name__=='__main__':
    *_,r=make();print(json.dumps({'status':r['status'],'code_bytes':r['code_bytes']}))
