"""Apply the existing photo/queued-reader matrix to the new CP composition."""
import json
from pathlib import Path
import build_lut_events_cp as build
import verify_lut_events_cp as boot
import verify_lut_photo_reader as photo


def main():
    original_owner=photo.readers.Owner
    class CurrentDescriptorOwner(original_owner):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            # A direct native producer now passes the same centralized cache
            # check as real callsites. Give this old fault fixture a current
            # descriptor instead of its formerly unchecked zero global bytes.
            self.u.mem_write(photo.v.G+0x68,bytes(self.u.mem_read(photo.own.CTX+0x18,96)))
        def apply(self,art=False):
            photo.v.put(self.u,photo.own.CTX+0x2c,124 if art else 0)
            self.u.mem_write(photo.v.G+0x68,bytes(self.u.mem_read(photo.own.CTX+0x18,96)))
            self.call(0x4e876c,photo.own.OWNER,photo.own.CTX)
    previous=photo.readers.coldcheck.cold
    try:
        photo.readers.Owner=CurrentDescriptorOwner
        photo.readers.coldcheck.cold=boot.cold
        photo.main(build,'photo-regression.json')
    finally:
        photo.readers.coldcheck.cold=previous
        photo.readers.Owner=original_owner
    path=build.OUT/'photo-regression.json';report=json.loads(path.read_text())
    report['status']='UPLOAD_CP_COMPOSITION_PHOTO_REGRESSION_VERIFIED_NOT_FLASHABLE'
    report['source_sha256'][Path(__file__).name]=build.b.sha(Path(__file__).read_bytes())
    report['source_sha256']['verify_lut_events_cp.py']=build.b.sha((build.b.HERE/'verify_lut_events_cp.py').read_bytes())
    report['limitations']=[
        'This photo-only harness supplies session/OS/driver fixtures; the real AP owner loop is verified separately.',
        'Central cached-context, loader and data-constructor entries are guarded; external ownership and unrelated memory readers remain unproven.',
        'MMIO, physical DMA, VFX profile submission, timing and final JPEG output are not hardware-validated.',
        'Fault quarantine is not physical DMA abort; WBI and production installer are unfinished.']
    path.write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
