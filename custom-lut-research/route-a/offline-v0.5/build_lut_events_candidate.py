"""Save the verified real-upload composition as a private offline AP/CP pair.

Does not call any camera/session/installer/transport API. New development output
only; frozen dev-menu-03 and its package are never modified.
"""
import json
import subprocess
import sys
from pathlib import Path
import build_lut_events_owner as apbuild
import build_lut_events_cp as cpbuild
b=apbuild.b
OUT=b.HERE/'dev-events-05'


def read(path):return json.loads(path.read_text())

def inverse(data,recipe):
    result=bytearray(data)
    for patch in recipe['patches']:
        at=patch['offset'];n=patch['length']
        assert bytes(result[at:at+n])==bytes.fromhex(patch['after'])
        result[at:at+n]=bytes.fromhex(patch['before'])
    return bytes(result)

def main():
    ap,ar=apbuild.make();cp,_,cr=cpbuild.make()
    report=read(apbuild.OUT/'verification.json');photo=read(cpbuild.OUT/'photo-regression.json')
    events=read(apbuild.OUT/'menu-events.json');readers=read(cpbuild.OUT/'reader-verification.json')
    assert report['ap_recipe_sha256']==b.sha((apbuild.OUT/'recipe.json').read_bytes())
    assert report['cp_recipe_sha256']==photo['recipe_sha256']==b.sha((cpbuild.OUT/'recipe.json').read_bytes())
    assert report['ap_sha256']==b.sha(ap) and report['cp_sha256']==photo['in_memory_cp_sha256']==b.sha(cp)
    assert events['ap_sha256']==b.sha(ap) and events['cp_sha256']==readers['cp_sha256']==b.sha(cp)
    assert events['ap_recipe_sha256']==report['ap_recipe_sha256']
    assert events['cp_recipe_sha256']==readers['recipe_sha256']==report['cp_recipe_sha256']
    for record in (ar,cr,report,photo,events,readers):
        for name,digest in record['source_sha256'].items():assert b.sha((b.HERE/name).read_bytes())==digest,name
    back=inverse(ap,ar);cut=ar['file_insertion']['offset'];n=ar['file_insertion']['bytes']
    back=back[:cut]+back[cut+n:]
    for folder in ('ap-sender-build','handoff-build'):back=inverse(back,read(b.HERE/'lifecycle-dev'/folder/'recipe.json'))
    assert back==(b.HERE/'dev-menu-03/candidate/appFw.so').read_bytes()
    back=inverse(cp,cr)
    for folder in ('native-reader-build','queue-allocation-build','cp-placement-build'):
        back=inverse(back,read(b.HERE/'lifecycle-dev'/folder/'recipe.json'))
    assert back==(b.HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    (OUT/'candidate').mkdir(parents=True,exist_ok=True)
    for name,data in (('appFw.so',ap),('cpapp-b.bin',cp)):
        path=OUT/'candidate'/name
        if path.exists():assert path.read_bytes()==data,'Existing candidate differs; use a new version'
        else:path.write_bytes(data)
    subprocess.run([sys.executable,str(b.HERE/'verify_menu.py'),str(OUT)],check=True,capture_output=True,text=True)
    menu_path=OUT/'menu-verification.json'
    menu=read(menu_path)
    assert menu['candidate_sha256']==b.sha(ap) and menu['camera_io'] is False
    assert menu['status']=='MENU_AND_SETTING_COMPONENT_VERIFIED_NOT_RELEASE_READY'
    assert menu['script_sha256']==b.sha((b.HERE/'verify_menu.py').read_bytes())
    hashes={name:b.sha(data) for name,data in (('appFw.so',ap),('cpapp-b.bin',cp))}
    report_paths={str(p.relative_to(b.HERE)):b.sha(p.read_bytes()) for p in
        (apbuild.OUT/'recipe.json',cpbuild.OUT/'recipe.json',apbuild.OUT/'verification.json',cpbuild.OUT/'photo-regression.json',apbuild.OUT/'menu-events.json',cpbuild.OUT/'reader-verification.json',menu_path)}
    readiness={'status':'NOT_READY_TO_FLASH','candidate':'dev-events-05','camera_io':False,
               'candidate_sha256':hashes,'hardware_adapter_available':False,
               'verified_upload_scope':['Actual native queue worker and select_lut task entry',
                   'Entropy-backed immutable session handshake without fixture core open',
                   'Permission before shared copy; persistent tagged async completion',
                   'Monotonic deadlines, explicit cancellation, late/duplicate callback isolation',
                   'Commit acknowledgment and committed-cancel resolution before secondary setting',
                   'Native clear path for built-in selection and deleted/missing slot',
                   'Native cancel virtual dispatch and RELATIVE relocation at three load biases',
                   'Native LUT/CUBE deletion entries drain transfer and await required clear before unlink',
                   'Reset event gates its native selective helper on confirmed publication',
                   'Central cached-context, loader and data-constructor entry guards cover direct and indirect calls',
                   'Native internal command-table reapply is idempotent only for the confirmed descriptor',
                   'Menu component regression bound to the complete new AP image',
                   'Exact inverse of both complete images to frozen dev-menu-03'],
               'blockers':['Physical kernel/OSAL/entropy/filesystem/interchip completion contract is untested.',
                   'A missing AP completion or CP DMA fault retains quarantine; no physical abort/recovery contract has been established.',
                   'Native cancel/delete/reset backend entries are integrated; complete UI key/popup producer, failure feedback and persistence are not validated.',
                   'Known external loaders and CP internal reapply are guarded; external allocation ownership, unrelated memory readers and early parameter reads remain unproven.',
                   'Cold-process session only; warm boot/WBI, live activation and production installer are incomplete.',
                   'AP file is 65536 bytes larger; the old fixed-window installation package is incompatible.',
                   'No camera cold boot, menu UI, preview/playback or full-size JPEG output has been tested.'],
               'reports':report_paths}
    manifest={'format':1,'name':'dev-events-05','target':'ILCE-7CM2 2.01 exact local FL23 baseline',
              'status':readiness['status'],'camera_io':False,'full_pair_written':True,
              'outputs':{name:{'sha256':hashes[name],'size':len(data)} for name,data in (('appFw.so',ap),('cpapp-b.bin',cp))},
              'frozen_parent':read(b.HERE/'dev-menu-03/readiness.json')['candidate_sha256'],
              'inverse_to_frozen_pair_verified':True,'reports':report_paths,
              'builder_sha256':b.sha(Path(__file__).read_bytes())}
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (OUT/'readiness.json').write_text(json.dumps(readiness,indent=2)+'\n')
    print(json.dumps({'candidate':str(OUT),'status':readiness['status'],'outputs':manifest['outputs'],
                      'inverse_to_frozen_pair':True,'camera_io':False}))


if __name__=='__main__':main()
