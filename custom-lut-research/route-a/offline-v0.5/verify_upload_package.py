"""Supplemental package checks for dev-menu-03, with zero camera access."""
import io
import json
import tempfile
from pathlib import Path
from elftools.elf.elffile import ELFFile
import build as b
from install_transaction import Package, Transaction, Rejected, digest
from native_pair_backend import FixedWindows
from verify_installer import ForbiddenDevice

HERE=Path(__file__).resolve().parent


def main():
    folder=HERE/'dev-menu-03'
    package=Package(HERE/'package-dev-menu-03')
    mraw=(folder/'manifest.json').read_bytes(); m=json.loads(mraw)
    rraw=(folder/'readiness.json').read_bytes(); readiness=json.loads(rraw)
    assert digest(mraw)==package.manifest['firmware_manifest_sha256']
    assert digest(rraw)==package.manifest['readiness_report_sha256']
    assert readiness['status']=='NOT_READY_TO_FLASH' and package.manifest['hardware_adapter_available'] is False
    assert readiness['audit_source_sha256']==digest((HERE/'audit_upload_candidate.py').read_bytes())
    for name,value in readiness['reports'].items():assert digest((folder/name).read_bytes())==value
    for source in m['build_sources']:assert digest((HERE/source['source']).read_bytes())==source['sha256']
    fixed=FixedWindows(package,mraw)
    assert len(fixed.windows)==21
    old=Package(HERE/'package-dev-menu-02')
    old_fixed=FixedWindows(old,(HERE/'dev-menu-02/manifest.json').read_bytes())
    historical=json.loads((HERE/'installer-evidence/native-write-order-verification.json').read_text())
    old_install=next(x for x in historical['native_execution'] if x['action']=='INSTALL')['actual_write_callbacks']
    assert [list(row) for row in old_fixed.install_order]==old_install
    assert old.key=='309bab664d2c67082406f857284f6ef0226bc98406391a718166cbf00f2d33d0'
    elf=ELFFile(io.BytesIO((b.BASE/'appFw.so').read_bytes()))
    start,end=m['upload_guards']['code_start'],m['upload_guards']['code_end']
    for section in elf.iter_sections():
        if section['sh_type']!='SHT_NOBITS' and section['sh_size']:
            assert section['sh_offset']+section['sh_size']<=start or section['sh_offset']>=end
        if hasattr(section,'iter_relocations'):
            for rel in section.iter_relocations():assert not start<=rel['r_offset']<end
    # No real service or transport is loaded, even when exercising the gate.
    with tempfile.TemporaryDirectory(prefix='lut-dev03-package-') as temp:
        device=ForbiddenDevice();device.write_scope='pair'
        with Transaction(package,Path(temp)/'journal') as t:
            try:t.install(device)
            except Rejected as error:assert str(error)=='Candidate is not released for controlled flashing'
            else:raise AssertionError('Unreleased candidate passed the gate')
            assert t.state['phase']=='NEW' and device.calls==[]
    order=json.loads((folder/'native-write-order-verification.json').read_text())
    assert order['package_sha256']==package.key and order['window_count']==21
    for name,value in order['sources'].items():assert digest((HERE/name).read_bytes())==value
    names=('verify_upload_package.py','native_write_order.py','native_pair_backend.py','install_transaction.py','verify_installer.py')
    report={'status':'OFFLINE_PACKAGE_VERIFIED_NOT_READY_TO_FLASH','camera_io':False,
            'package_sha256':package.key,'candidate_sha256':package.expected('candidate'),
            'manifest_and_readiness_bound':True,'previous_package_unchanged':True,
            'previous_install_order_unchanged':True,'new_code_avoids_original_sections_and_relocations':True,
            'window_count':21,'release_gate':'REJECTED_BEFORE_DEVICE_ACCESS','device_methods_invoked':[],
            'source_hashes':{n:digest((HERE/n).read_bytes()) for n in names},
            'native_order_report_sha256':digest((folder/'native-write-order-verification.json').read_bytes()),
            'hardware_adapter_available':False}
    (folder/'package-verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('status','package_sha256','window_count','release_gate')}))

if __name__=='__main__':main()
