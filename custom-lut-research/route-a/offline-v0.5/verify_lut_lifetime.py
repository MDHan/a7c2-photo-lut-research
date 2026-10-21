"""Execute new atomic lifecycle code and tagged native VFX callbacks offline.

No candidate images or frozen reports are modified. Production cell allocation,
load/submit hooks and cross-reader ownership remain deliberately unresolved.
"""
import hashlib
import itertools
import json
from pathlib import Path
import struct

import build as b
import verify_vfx_completion as completion

v = completion.v
HERE = Path(__file__).resolve().parent
OUT = HERE / 'lifecycle-dev'
BRIDGE = 0xc2f950
CORE = 0xc2fa00
WRAPPER = 0xc2fe00
CELLS = (v.RAM + 0x7000, v.RAM + 0x7010)
FREE, FAULT = 0x80, 0x40


def compile_parts(cells=CELLS):
    bridge, bs, bm = b.compile_source('vfx_callback_tag.S', 'armv7a-none-eabi', OUT)
    core, cs, cm = b.compile_source('photo_lut_lifetime.c', 'armv7a-none-eabi', OUT)
    wrapper, ws, wm = b.compile_source('lifecycle-dev/callback_fixture.S', 'armv7a-none-eabi', OUT)
    for name, target in [('vfx_tag_capture_resume', 0xbb353e),
                         ('vfx_tag_deliver_resume', 0xbb3610)]:
        at = bs[name]
        bridge[at:at+4] = b.branch32(BRIDGE+at, target)
    for name, target in [('callback0_resume', 0xb1920a), ('callback1_resume', 0xb19216)]:
        at = ws[name]
        wrapper[at:at+4] = b.branch32(WRAPPER+at, target)
    for name, target in [('cell0_address', cells[0]), ('cell1_address', cells[1]),
                         ('record_address', CORE+cs['pll_vfx_complete'])]:
        struct.pack_into('<I', wrapper, ws[name], target)
    assert BRIDGE+len(bridge) <= CORE and CORE+len(core) <= WRAPPER
    assert WRAPPER+len(wrapper) <= 0xc30000
    return bridge, bs, core, cs, wrapper, ws, [bm, cm, wm]


class Integrated(completion.Completion):
    def __init__(self, cp, parts):
        bridge, bs, core, cs, wrapper, ws, _ = parts
        patched = bytearray(cp)
        # First snapshot is already under the native slot semaphore. fp is
        # saved/restored by the containing native function and otherwise unused.
        for at, expected, replacement in [
            (0xbb353a, bytes.fromhex('d9f80880'), b.branch32(0xbb353a, BRIDGE+(bs['vfx_tag_capture']&~1))),
            (0xbb3608, bytes.fromhex('50f834100020c047'), b.branch32(0xbb3608, BRIDGE+(bs['vfx_tag_deliver']&~1))+bytes.fromhex('00bf00bf')),
        ]:
            off = at-b.CP_DELTA
            assert patched[off:off+len(expected)] == expected, hex(at)
            patched[off:off+len(expected)] = replacement
        self.parts = parts
        self.core_symbols = cs
        self.wrapper_symbols = ws
        self.tag_seen = []
        super().__init__(bytes(patched))
        for at, blob in ((BRIDGE, bridge), (CORE, core), (WRAPPER, wrapper)):
            # These unused-tail placements are an emulation fixture. No file or
            # boot mapping is extended, and state lives in harness RAM only.
            assert not any(cp[at-b.CP_DELTA:at-b.CP_DELTA+len(blob)])
            self.u.mem_write(at, bytes(blob))
        for cell in CELLS:
            v.put(self.u, cell, FREE)

    def code(self, u, pc, size, unused):
        bridge, bs, core, cs, wrapper, ws, _ = self.parts
        if pc in (WRAPPER+(ws['photo_context0']&~1), WRAPPER+(ws['photo_context1']&~1)):
            self.tag_seen.append([pc, *[u.reg_read(v.reg(i)) for i in range(4)]])
        if any(at <= pc < at+len(blob) for at, blob in ((BRIDGE, bridge), (CORE, core), (WRAPPER, wrapper))):
            return
        super().code(u, pc, size, unused)

    def core(self, name, cell, *args):
        return self.call(CORE+(self.core_symbols[name]&~1), cell, *args)

    def tagged_register(self, channel, context, tag):
        callback = WRAPPER+self.wrapper_symbols['photo_context'+str(context)]
        self.u.mem_write(completion.PARAMS, struct.pack('<2I', tag, callback))
        self.call(0xbb22d8, channel, completion.PARAMS)
        assert not any(self.locks.values())


def main():
    cp = (HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    assert hashlib.sha256(cp).hexdigest() == completion.release.EXPECTED_CP
    parts = compile_parts()
    n = Integrated(cp, parts)
    cell = CELLS[0]
    permutations = 0
    for order in itertools.permutations(range(6)):
        tag = n.core('pll_begin', cell, 15)
        assert tag and n.core('pll_begin', cell, 15) == 0
        for index, event in enumerate(order):
            assert n.core('pll_take_release', cell, tag) == 0
            if event < 4:
                assert n.core('pll_vfx_complete', cell, tag, event+3, 0) == 1
            else:
                assert n.core('pll_load_complete' if event == 4 else 'pll_submit_complete', cell, tag, 1) == 1
            if index < 5:
                assert n.core('pll_take_release', cell, tag) == 0
        assert n.core('pll_take_release', cell, tag) == 1
        assert n.core('pll_take_release', cell, tag) == 0
        assert n.core('pll_vfx_complete', cell, tag, 3, 0) == 0
        assert n.core('pll_release_complete', cell, tag, 1) == 1
        assert n.core('pll_release_complete', cell, tag, 1) == 0
        permutations += 1

    fault_cases = []
    for failure in ('load', 'submit', 'callback', 'timeout', 'release'):
        v.put(n.u, cell, FREE)  # new isolated test, never a runtime recovery API
        tag = n.core('pll_begin', cell, 15)
        if failure == 'load': n.core('pll_load_complete', cell, tag, 0)
        elif failure == 'submit': n.core('pll_submit_complete', cell, tag, 0)
        elif failure == 'callback': n.core('pll_vfx_complete', cell, tag, 3, 9)
        elif failure == 'timeout': n.core('pll_fault', cell, tag)
        for ch in range(3, 7): n.core('pll_vfx_complete', cell, tag, ch, 0)
        n.core('pll_load_complete', cell, tag, 1)
        n.core('pll_submit_complete', cell, tag, 1)
        if failure == 'release':
            assert n.core('pll_take_release', cell, tag) == 1
            assert n.core('pll_release_complete', cell, tag, 0) == 1
        assert v.word(n.u, cell) & FAULT
        assert n.core('pll_take_release', cell, tag) == 0
        assert n.core('pll_begin', cell, 15) == 0
        assert n.core('pll_release_complete', cell, tag, 1) == 0
        fault_cases.append(failure)

    # Epoch exhaustion never wraps into a valid previous callback tag.
    v.put(n.u, cell, 0xffffff80)
    assert n.core('pll_begin', cell, 1) == 0
    for invalid in (0, 16, 0xffffffff):
        v.put(n.u, cell, FREE)
        assert n.core('pll_begin', cell, invalid) == 0
    v.put(n.u, cell, FREE)
    tag = n.core('pll_begin', cell, 1)
    before = v.word(n.u, cell)
    for invalid in (0, 2, 0x100, 0x103, 0xffffff02):
        for fn, args in [('pll_vfx_complete', (3, 0)), ('pll_load_complete', (1,)),
                         ('pll_submit_complete', (1,)), ('pll_fault', ()),
                         ('pll_take_release', ()), ('pll_release_complete', (1,))]:
            assert n.core(fn, cell, invalid, *args) == 0
            assert v.word(n.u, cell) == before

    original_callback_cases = 0
    for channel, completed in itertools.product(range(4), range(16)):
        n = Integrated(cp, parts)
        n.register(channel, 0x32)  # original untagged callback remains unchanged
        n.configure_gate(channel, completed)
        n.call(0xbb34d4, channel)
        assert n.flags[0x32] == ((1 << (channel+12)) if completed == 15 else 0)
        assert all(v.word(n.u, c) == FREE for c in CELLS)
        original_callback_cases += 1

    # Actual native registration, gate, FIFO promotion, tag bridge, compiled
    # callback recorder, and original photo event callback execute together.
    integrated = []
    for mask in range(1, 16):
        n = Integrated(cp, parts)
        tags = [n.core('pll_begin', c, mask) for c in CELLS]
        # Make epochs different to detect retrieving the promoted slot's tag.
        # Finish context 1 once, then start its second generation.
        for ch in range(3, 7): n.core('pll_vfx_complete', CELLS[1], tags[1], ch, 0)
        n.core('pll_load_complete', CELLS[1], tags[1], 1)
        n.core('pll_submit_complete', CELLS[1], tags[1], 1)
        assert n.core('pll_take_release', CELLS[1], tags[1]) == 1
        n.core('pll_release_complete', CELLS[1], tags[1], 1)
        tags[1] = n.core('pll_begin', CELLS[1], mask)
        assert tags == [0x102, 0x202]
        for context in (0, 1):
            n.core('pll_load_complete', CELLS[context], tags[context], 1)
            n.core('pll_submit_complete', CELLS[context], tags[context], 1)
            for ch in range(4):
                if mask & (1 << ch): n.tagged_register(ch, context, tags[context])
        for context in (0, 1):
            for ch in range(4):
                if not mask & (1 << ch): continue
                n.configure_gate(ch, 15)
                n.call(0xbb34d4, ch)
                assert n.tag_seen[-1][1:] == [0, 0x12345678, ch+3, tags[context]]
            assert n.flags[0x32+context] == mask << 12
            assert n.core('pll_take_release', CELLS[context], tags[context]) == 1
            n.core('pll_release_complete', CELLS[context], tags[context], 1)
        # Inject an old native registration AFTER storage was reused. This is
        # a fault fixture, not a claim native hardware produces late duplicates.
        fresh = n.core('pll_begin', CELLS[0], mask)
        before = v.word(n.u, CELLS[0])
        ch = (mask & -mask).bit_length()-1
        n.flags[0x32] = 0
        n.tagged_register(ch, 0, tags[0])
        n.configure_gate(ch, 15)
        n.call(0xbb34d4, ch)
        assert v.word(n.u, CELLS[0]) == before
        assert n.flags[0x32] == 0
        assert n.core('pll_take_release', CELLS[0], fresh) == 0
        integrated.append({'enabled_mask': mask, 'registered_tags': tags,
                           'native_callback_tag_order': [x[4] for x in n.tag_seen],
                           'stale_tag_does_not_complete_new_photo': True,
                           'current_native_event_forwarded_stale_event_suppressed': True})

    bridge, bs, core, cs, wrapper, ws, sources = parts
    blobs = {'tag-bridge.bin': bridge, 'lifecycle-core.bin': core,
             'offline-callback-fixture.bin': wrapper}
    for name, raw in blobs.items(): (OUT/name).write_bytes(raw)
    report = {'status': 'EXPERIMENTAL_COMPONENT_NOT_READY_TO_FLASH', 'camera_io': False,
              'candidate_unchanged': True, 'cp_sha256': hashlib.sha256(cp).hexdigest(),
              'all_completion_orderings': permutations, 'original_callback_cases': original_callback_cases, 'fault_cases': fault_cases,
              'integrated_native_cases': integrated, 'epoch_wrap_rejected': True,
              'invalid_masks_and_tags_rejected': True,
              'component_sizes': {'tag_bridge': len(bridge), 'lifecycle_core': len(core),
                                  'offline_callback_fixture': len(wrapper)},
              'component_symbols': cs, 'compiler_sources': sources,
              'payload_sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in blobs.items()},
              'emulated_hooks': [{'address': '0xbb353a', 'original': 'd9f80880',
                                  'purpose': 'snapshot registration word with callback under native slot lock'},
                                 {'address': '0xbb3608', 'original': '50f834100020c047',
                                  'purpose': 'deliver captured registration word as fourth argument'}],
              'dependency_sha256': {name: hashlib.sha256((HERE/name).read_bytes()).hexdigest()
                                    for name in ('build.py', 'verify_vfx_completion.py',
                                                 'verify_resource_release.py', 'verify.py')},
              'test_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'header_sha256': hashlib.sha256((HERE/'photo_lut_lifetime.h').read_bytes()).hexdigest(),
              'production_gaps': ['writable state allocation and boot initialization',
                                  'load/submit/error hooks tied to real request identity',
                                  'all native readers and shared upload ownership',
                                  'verified drain and release API integration',
                                  'full scheduler and interrupt interleavings']}
    (OUT/'verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'completion_orders': permutations, 'fault_cases': len(fault_cases),
                      'integrated_native_cases': len(integrated), 'original_callback_cases': original_callback_cases, 'sizes': report['component_sizes'],
                      'status': report['status']}))


if __name__ == '__main__': main()
