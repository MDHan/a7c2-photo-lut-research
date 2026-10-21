"""Apply the existing photo/queued-reader matrix to the new CP composition."""
import json
from pathlib import Path
import build_lut_upload_cp as build
import verify_lut_upload_cp as boot
import verify_lut_photo_reader as photo


def main():
    previous=photo.readers.coldcheck.cold
    try:
        photo.readers.coldcheck.cold=boot.cold
        photo.main(build,'photo-regression.json')
    finally:photo.readers.coldcheck.cold=previous
    path=build.OUT/'photo-regression.json';report=json.loads(path.read_text())
    report['status']='UPLOAD_CP_COMPOSITION_PHOTO_REGRESSION_VERIFIED_NOT_FLASHABLE'
    report['source_sha256'][Path(__file__).name]=build.b.sha(Path(__file__).read_bytes())
    report['source_sha256']['verify_lut_upload_cp.py']=build.b.sha((build.b.HERE/'verify_lut_upload_cp.py').read_bytes())
    report['limitations']=[
        'This photo-only harness supplies session/OS/driver fixtures; the real AP owner loop is verified separately.',
        'Four native cached consumers are guarded, but the complete external-reader/callback graph remains unproven.',
        'MMIO, physical DMA, VFX profile submission, timing and final JPEG output are not hardware-validated.',
        'Fault quarantine is not physical DMA abort; WBI and production installer are unfinished.']
    path.write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
