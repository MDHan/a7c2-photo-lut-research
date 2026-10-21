"""Build the CP publication receiver; placement/transport adapter are pending."""
import json
import build_lut_native_reader as parent
base=parent.base
HERE=base.HERE
OUT=HERE/'lifecycle-dev/cp-publication-build'


def make():
    cp,payload,pr=parent.make()
    core=json.loads((base.parent.parent.OUT/'recipe.json').read_text())['core_addresses']
    OUT.mkdir(exist_ok=True)
    (OUT/'layout.h').write_text(''.join('#define '+name+' '+hex(core[symbol])+'U\n' for name,symbol in
                                       [('CP_REQUEST','lh_cp_request'),('CP_PUBLISHED','lh_cp_published')]))
    code,symbols,compile=base.b.compile_source('lut_cp_publication.c','armv7a-none-eabi',OUT)
    r={'status':'CP_PUBLICATION_COMPONENT_NOT_IN_FIRMWARE','camera_io':False,'full_image_written':False,
       'code_bytes':len(code),'state_bytes':116,'symbols':{k:v for k,v in symbols.items() if k},
       'payload_sha256':base.b.sha(code),'parent_cp_sha256':pr['in_memory_cp_sha256'],
       'parent_recipe_sha256':base.b.sha((parent.OUT/'recipe.json').read_bytes()),
       'compile':compile,'native_ipc_receiver_connected':False,'native_reply_transport_connected':False,
       'source_sha256':{name:base.b.sha((HERE/name).read_bytes()) for name in
                        ('build_lut_cp_publication.py','lut_cp_publication.c','lut_cp_publication.h',
                         'lut_handoff_cp.h','lut_handoff_ap.h','lifecycle-dev/cp-publication-build/layout.h')}}
    (OUT/'publication.bin').write_bytes(code)
    (OUT/'component.json').write_text(json.dumps(r,indent=2)+'\n')
    return cp,payload,pr,bytes(code),r


if __name__=='__main__':
    *_,r=make();print(json.dumps({k:r[k] for k in ('status','code_bytes','state_bytes')}))
