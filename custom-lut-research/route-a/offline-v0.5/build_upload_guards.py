"""Derive a separate dev-menu-03 image from exact dev-menu-02, offline only."""
import argparse
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import build as b

BASE = b.HERE / 'dev-menu-02'
EXPECTED = {'appFw.so': 'a3bffb09002988c4873122b6db41a2e23c87c2a66ff82a2d53b0fdb6959f533d',
            'cpapp-b.bin': '48ff01e346ac74e78b61f811725c0bd95ab2712938b55ad607a5b2f54a3bf4e1'}


def branch(src, dst, link=False):
    word = struct.unpack('<I', b.branch64(src, dst))[0]
    return struct.pack('<I', word | (0x80000000 if link else 0))


def adrp(src, dst, reg):
    delta = ((dst & ~4095) - (src & ~4095)) >> 12
    assert -(1 << 20) <= delta < (1 << 20)
    imm = delta & 0x1fffff
    return struct.pack('<I', 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | reg)


def build(out):
    manifest = json.loads((BASE / 'manifest.json').read_text())
    assert {k: v['sha256'] for k, v in manifest['outputs'].items()} == EXPECTED
    raw = {n: (BASE / 'candidate' / n).read_bytes() for n in EXPECTED}
    assert {n: b.sha(data) for n, data in raw.items()} == EXPECTED
    for source in manifest['build_sources']:
        assert b.sha((b.HERE / source['source']).read_bytes()) == source['sha256']
    out.mkdir(parents=True, exist_ok=False)
    (out / 'candidate').mkdir()
    code, symbols, source = b.compile_source('lut_upload_guards.S', 'aarch64-none-elf', out)
    start = b.AP_CODE + manifest['placement']['ap_bytes']
    assert start % 4 == 0
    resolved = []
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for label, target, link in [('lut_read_size_resume', 0x3428600, False),
                                 ('lut_native_map_call', 0x34d37e8, True),
                                 ('lut_failed_map_close', 0x165f430, True)]:
        at = symbols[label]
        code[at:at+4] = branch(start+at, target, link)
        insn = next(decoder.disasm(code[at:at+4], start+at))
        assert insn.mnemonic == ('bl' if link else 'b') and int(insn.op_str[1:], 16) == target
        resolved.append({'symbol': label, 'address': start+at, 'target': target})
    for label, target in [('lut_special_buffer_page', 0x5b7e8f8), ('lut_regular_buffer_page', 0x5b8f438)]:
        at = symbols[label]
        code[at:at+4] = adrp(start+at, target, 11)
        insn = next(decoder.disasm(code[at:at+4], start+at))
        assert insn.mnemonic == 'adrp' and int(insn.op_str.split('#')[1], 16) == target & ~4095
        resolved.append({'symbol': label, 'address': start+at, 'target': target})
    end = start + len(code)
    assert end <= 0x51a7718 and (end+0xffff)//0x10000 == (start+0xffff)//0x10000
    ap = bytearray(raw['appFw.so'])
    assert ap[start:end] == bytes(len(code))
    ap[start:end] = code
    # Extend the existing body window, retaining its original baseline bytes.
    body = next(p for p in manifest['patches'] if p['file'] == 'appFw.so' and p['offset'] == b.AP_CODE)
    assert body['length'] == start-b.AP_CODE
    body['before'] += bytes(len(code)).hex(); body['after'] += code.hex(); body['length'] += len(code)
    body['purpose'] += '; LUT byte-count and mapping-failure guards'
    for at in (0x60, 0x68):
        p = next(p for p in manifest['patches'] if p['file'] == 'appFw.so' and p['offset'] == at)
        assert struct.unpack_from('<Q', ap, at)[0] == start
        ap[at:at+8] = struct.pack('<Q', end); p['after'] = ap[at:at+8].hex()
    for at, label, target, link in [(0x34285fc, 'lut_read_size_guard', None, False),
                                    (0x3021184, 'lut_checked_mapping', 0x34d37e8, True)]:
        before = bytes(ap[at:at+4])
        if target: assert before == branch(at, target, True)
        else: assert before == bytes.fromhex('1f1c0072') # tst w0,#0xff
        for p in manifest['patches']:
            if p['file'] == 'appFw.so': assert at+4 <= p['offset'] or p['offset']+p['length'] <= at
        after = branch(at, start+symbols[label], link); ap[at:at+4] = after
        manifest['patches'].append({'file': 'appFw.so', 'offset': at, 'offset_hex': hex(at), 'length': 4,
                                   'before': before.hex(), 'after': after.hex(), 'purpose': label})
    raw['appFw.so'] = bytes(ap)
    for n, data in raw.items():
        (out / 'candidate' / n).write_bytes(data)
        manifest['outputs'][n] = {'sha256': b.sha(data), 'size': len(data)}
    manifest['placement']['ap_bytes'] = end-b.AP_CODE
    manifest['upload_guards'] = {'code_start': start, 'code_end': end,
                                'symbols': {k: start+v for k, v in symbols.items()}, 'resolved': resolved,
                                'scope': 'Native user LUT select/upload; malformed short data rejected in still and movie modes; checked mapping only in LUT uploader.',
                                'format_integrity_or_concurrency_proven': False}
    manifest['build_sources'] += [source, {'source': Path(__file__).name, 'sha256': b.sha(Path(__file__).read_bytes()),
                                         'command': ['python', Path(__file__).name, '--output', str(out)]}]
    manifest['parent_candidate'] = {'name': 'dev-menu-02', 'sha256': EXPECTED}
    manifest['status'] = 'NOT_READY_TO_FLASH'
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    (out / 'SHA256SUMS').write_text(''.join(f"{v['sha256']}  candidate/{n}\n" for n,v in manifest['outputs'].items()))
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.output)['outputs'], indent=2))
