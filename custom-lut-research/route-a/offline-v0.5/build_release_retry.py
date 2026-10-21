"""Append inactivity-release result handling to the offline tracked CP.

Only component bytes and reversible recipes are written. No full image/package
or device adapter is produced, and frozen dev-menu-03 files are not edited.
"""
import hashlib
import json
import struct
from pathlib import Path
import build as b
import build_tracked_entry as tracked

HERE = Path(__file__).resolve().parent
OUT = HERE / 'lifecycle-dev/release-build'
SITE = 0x4e7f50
RESUME = 0x4e7f90


def make():
    previous, old = tracked.make()
    OUT.mkdir(exist_ok=True)
    raw, symbols, source = b.compile_source('lut_idle_release.S', 'armv7a-none-eabi', OUT)
    start = b.CP_CODE + old['payload_size']
    assert start % 4 == 0
    assert start + len(raw) <= 0xc30000
    off = symbols['lut_idle_release_resume']
    raw[off:off+4] = b.branch32(start + off, RESUME)
    expected = bytes.fromhex('02201de0')
    assert previous[SITE-b.CP_DELTA:SITE-b.CP_DELTA+4] == expected
    updated = bytearray(previous)
    patches = []
    for offset, after, purpose in [
        (start-b.CP_DELTA, bytes(raw), 'inactivity release result handler'),
        (0x20128, struct.pack('<I', start+len(raw)-0x128000), 'declared executable extent'),
        (SITE-b.CP_DELTA, b.branch32(SITE, start), 'check native release result'),
    ]:
        before = previous[offset:offset+len(after)]
        assert len(before) == len(after)
        updated[offset:offset+len(after)] = after
        patches.append({'offset': offset, 'length': len(after), 'before': before.hex(),
                        'after': after.hex(), 'purpose': purpose})
    inverse = bytearray(updated)
    for p in patches:
        inverse[p['offset']:p['offset']+p['length']] = bytes.fromhex(p['before'])
    assert bytes(inverse) == previous
    for p in old['patches']:
        inverse[p['offset']:p['offset']+p['length']] = bytes.fromhex(p['before'])
    assert hashlib.sha256(inverse).hexdigest() == old['base_cp_sha256']
    report = {
        'status': 'EXPERIMENTAL_RELEASE_RETRY_NOT_READY_TO_FLASH',
        'camera_io': False, 'full_image_written': False,
        'previous_cp_sha256': hashlib.sha256(previous).hexdigest(),
        'in_memory_cp_sha256': hashlib.sha256(updated).hexdigest(),
        'base_cp_sha256': old['base_cp_sha256'],
        'address': start, 'size': len(raw), 'patches': patches,
        'source': source, 'builder_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'tracked_recipe_sha256': hashlib.sha256((tracked.OUT/'recipe.json').read_bytes()).hexdigest(),
        'inverse_to_previous_exact': True, 'inverse_to_frozen_exact': True,
    }
    (OUT/'release-retry.bin').write_bytes(raw)
    (OUT/'recipe.json').write_text(json.dumps(report, indent=2)+'\n')
    # Runtime layout for existing entry/boot emulators; tracked code is unchanged.
    layout = dict(old)
    layout['payload_size'] = start + len(raw) - b.CP_CODE
    layout['in_memory_cp_sha256'] = report['in_memory_cp_sha256']
    return bytes(updated), layout, report


if __name__ == '__main__':
    _, _, report = make()
    print(json.dumps({'address': hex(report['address']), 'size': report['size'],
                      'status': report['status']}))
