"""Build dev-menu-02: remove only the four still PASM PPLUT exclusions.

Uses original native rule machinery. No camera imports. The prior candidate
and builder remain unchanged. This is not a flash-ready release.
"""
import argparse
import io
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
import build as b

DESCRIPTORS = (0x5245e00, 0x5245de0, 0x5245e10, 0x5245df0)  # P, A, S, M
ACTION_ARRAYS = (0x422bbf0, 0x422bb90, 0x422bc30, 0x422bbc0)


def build(output):
    manifest = b.build(output)
    path = output / 'candidate/appFw.so'
    raw = bytearray(path.read_bytes())
    elf = ELFFile(io.BytesIO(raw))
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']

    def offset(va):
        found = [s['p_offset'] + va - s['p_vaddr'] for s in segments
                 if s['p_vaddr'] <= va < s['p_vaddr'] + s['p_filesz']]
        assert len(found) == 1
        return found[0]

    def patch(at, before, after, purpose):
        assert len(before) == len(after) and raw[at:at + len(before)] == before
        for p in manifest['patches']:
            if p['file'] == 'appFw.so':
                assert at + len(before) <= p['offset'] or p['offset'] + p['length'] <= at
        raw[at:at + len(before)] = after
        manifest['patches'].append({'file': 'appFw.so', 'offset': at, 'offset_hex': hex(at),
                                   'length': len(before), 'before': before.hex(), 'after': after.hex(),
                                   'purpose': purpose})

    # Prove descriptor pointer relocations and unique relocated consumers.
    relocations = []
    for section in elf.iter_sections():
        if hasattr(section, 'iter_relocations'):
            for index, r in enumerate(section.iter_relocations()):
                relocations.append((section['sh_offset'] + index * section['sh_entsize'], r.entry))
    assert struct.unpack_from('<QII', raw, offset(0x554c380)) == (0x5d830e0, 0x3f5, 0x14d)
    evidence = []
    for index, (descriptor, actions) in enumerate(zip(DESCRIPTORS, ACTION_ARRAYS)):
        count = 5 if index == 0 else 4
        assert struct.unpack_from('<QI', raw, offset(descriptor)) == (actions, count)
        assert struct.unpack_from('<Q', raw, offset(0x5d830e0 + index * 8))[0] == descriptor
        consumers = [r for _, r in relocations if r.get('r_addend') == descriptor]
        assert len(consumers) == 1 and consumers[0]['r_offset'] == 0x5d830e0 + index * 8
        assert consumers[0]['r_info_type'] == 1027 and consumers[0]['r_info_sym'] == 0
        own = [(at, r) for at, r in relocations if r['r_offset'] == descriptor]
        assert len(own) == 1
        reloc_at, reloc = own[0]
        assert reloc['r_info_type'] == 1027 and reloc['r_info_sym'] == 0 and reloc['r_addend'] == actions
        for profile in range(4):
            assert struct.unpack_from('<III', raw, offset(actions) + profile * 12) == (0, 0x3121 + profile, 0x3115)
        if index == 0:
            # P's fifth action applies to PP_PRM_ALL; retain it verbatim.
            assert struct.unpack_from('<III', raw, offset(actions) + 48) == (0, 0x3125, 0x3115)
            patch(offset(descriptor), struct.pack('<Q', actions), struct.pack('<Q', actions + 48),
                  'Still P rule: retain only the original PP_PRM_ALL action')
            patch(reloc_at + 16, struct.pack('<q', actions), struct.pack('<q', actions + 48),
                  'Match existing R_AARCH64_RELATIVE addend to retained P action')
        patch(offset(descriptor) + 8, struct.pack('<I', count), struct.pack('<I', 1 if index == 0 else 0),
              'Remove PPLUT-only exclusions for still ' + 'PASM'[index])
        evidence.append({'mode': 'PASM'[index], 'descriptor': hex(descriptor),
                         'unique_rule_array_slot': hex(0x5d830e0 + index * 8),
                         'relocation_offset': hex(reloc_at)})
    path.write_bytes(raw)
    manifest['outputs']['appFw.so'] = {'sha256': b.sha(raw), 'size': len(raw)}
    manifest['dynamic_menu_patch'] = {'scope': 'PPLUT1-4 in still P/A/S/M exposure rules only',
                                      'descriptors': evidence,
                                      'other_rules_modified': False,
                                      'full_event_loop_verified': False}
    for source in ('build.py', 'build_dynamic_menu.py'):
        manifest['build_sources'].append({'source': source, 'sha256': b.sha((b.HERE / source).read_bytes()),
                                          'command': ['python', 'build_dynamic_menu.py', '--output', str(output)]})
    manifest['status'] = 'NOT_READY_TO_FLASH'
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (output / 'SHA256SUMS').write_text(''.join(f"{v['sha256']}  candidate/{n}\n" for n, v in manifest['outputs'].items()))
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = build(args.output)
    print(json.dumps({'status': manifest['status'], 'outputs': manifest['outputs']}, indent=2))
