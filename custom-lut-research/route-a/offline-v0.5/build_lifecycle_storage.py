"""Exact-build BSS extension recipe; produces component files, no flash image."""
import hashlib
import json
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
import build as b

HERE = Path(__file__).resolve().parent
OUT = HERE/'lifecycle-dev'
CP_HASH = '48ff01e346ac74e78b61f811725c0bd95ab2712938b55ad607a5b2f54a3bf4e1'
BSS_START, OLD_SIZE = 0x120a000, 0x97bf5c
STATE_BASE = BSS_START+OLD_SIZE
CELLS = (STATE_BASE, STATE_BASE+4)
NEW_SIZE = OLD_SIZE+8
INIT = 0xc2fe80


def arm_branch(src, dst):
    delta = dst-src-8
    assert delta % 4 == 0 and -(1 << 25) <= delta < (1 << 25)
    raw = struct.pack('<I', 0xea000000 | ((delta >> 2) & 0xffffff))
    i = next(Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(raw, src))
    assert i.mnemonic == 'b' and int(i.op_str[1:], 16) == dst
    return raw


def make(cp):
    assert hashlib.sha256(cp).hexdigest() == CP_HASH
    assert struct.unpack_from('<3I', cp, 0x20148) == (0x10e2000, OLD_SIZE, BSS_START)
    assert struct.unpack_from('<3I', cp, 0x20154) == (0, 0x4000, 0x1b88000)
    assert STATE_BASE % 4 == 0 and STATE_BASE+8 <= 0x1b86000 < 0x1b88000
    code, symbols, source = b.compile_source('photo_lut_storage.S', 'armv7a-none-eabi', OUT)
    at = symbols['photo_lut_storage_resume']
    code[at:at+4] = arm_branch(INIT+at, 0x60d35c)
    # Only the low immediate part changes; movt r3,#0x1b8 remains intact.
    oldmov = struct.unpack_from('<I', cp, 0x60d338-b.CP_DELTA)[0]
    assert oldmov == 0xe3053f5c
    newmov = 0xe3053f64
    old_text = struct.unpack_from('<I', cp, 0x20128)[0]
    assert 0x128000+old_text == 0xc2f94e
    assert INIT+len(code) <= 0xc30000
    changes = [(0x20128, struct.pack('<I', old_text), struct.pack('<I', INIT+len(code)-0x128000), 'declared executable extent'),
               (0x2014c, struct.pack('<I', OLD_SIZE), struct.pack('<I', NEW_SIZE), 'declared BSS size'),
               (0x60d338-b.CP_DELTA, struct.pack('<I', oldmov), struct.pack('<I', newmov), 'native BSS clear end'),
               (0x60d358-b.CP_DELTA, bytes.fromhex('00000ae3'), arm_branch(0x60d358, INIT), 'initialize before CPU publication'),
               (INIT-b.CP_DELTA, bytes(len(code)), bytes(code), 'ARM initialization payload')]
    result = bytearray(cp)
    for offset, before, after, _ in changes:
        assert len(before) == len(after) and result[offset:offset+len(before)] == before
        result[offset:offset+len(before)] = after
    manifest = {'status': 'EXPERIMENTAL_STORAGE_RECIPE_NOT_READY_TO_FLASH',
                'camera_io': False, 'base_cp_sha256': CP_HASH,
                'in_memory_output_sha256': hashlib.sha256(result).hexdigest(),
                'bss_start': hex(BSS_START), 'old_bss_end': hex(STATE_BASE),
                'new_bss_end': hex(STATE_BASE+8), 'cells': [hex(x) for x in CELLS],
                'next_mapped_region': '0x1b88000', 'initialization_address': hex(INIT),
                'source': source, 'build_script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'payload_sha256': hashlib.sha256(code).hexdigest(),
                'patches': [{'offset': a, 'before': x.hex(), 'after': y.hex(), 'purpose': purpose}
                            for a, x, y, purpose in changes],
                'full_image_written': False}
    return bytes(result), bytes(code), manifest


def main():
    cp = (HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    _, code, manifest = make(cp)
    (OUT/'storage-init.bin').write_bytes(code)
    (OUT/'storage-recipe.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'status': manifest['status'], 'cells': manifest['cells'], 'bytes': len(code)}))


if __name__ == '__main__': main()
