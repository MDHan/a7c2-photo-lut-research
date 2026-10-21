"""Build a freestanding CP lease component, not a patched CP image."""
import json
from pathlib import Path
import build as b
HERE=b.HERE
OUT=HERE/'lifecycle-dev/cp-handoff-build'


def make():
    OUT.mkdir(exist_ok=True)
    raw,symbols,compiler=b.compile_source('lut_handoff_cp.c','armv7a-none-eabi',OUT)
    symbols={k:v for k,v in symbols.items() if k}
    report={'status':'CP_LEASE_COMPONENT_NOT_IN_FIRMWARE','camera_io':False,
            'code_bytes':len(raw),'state_bytes':148,'symbols':symbols,
            'payload_sha256':b.sha(raw),'compile':compiler,
            'full_image_written':False,'native_reader_hooks_connected':False,
            'native_ipc_receiver_connected':False,
            'source_sha256':{name:b.sha((HERE/name).read_bytes()) for name in
                             ('lut_handoff_ap.h','lut_handoff_cp.h','lut_handoff_cp.c','build_lut_handoff_cp.py')}}
    (OUT/'cp-handoff.bin').write_bytes(raw)
    (OUT/'component.json').write_text(json.dumps(report,indent=2)+'\n')
    return bytes(raw),report


if __name__=='__main__':
    _,r=make();print(json.dumps({k:r[k] for k in ('status','code_bytes','state_bytes')}))
