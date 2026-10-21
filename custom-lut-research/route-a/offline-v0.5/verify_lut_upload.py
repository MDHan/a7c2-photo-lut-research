"""Execute native AP file upload/message + CP descriptor receive, offline only.

libc filesystem/mapping and interchip completion are explicit fixtures. These
cases prove native decisions/data flow, not hardware transfer or thread order.
"""
import hashlib
import json
import struct
from pathlib import Path
from unicorn import UC_HOOK_CODE
from unicorn import arm_const as ar
import verify_menu as menu
import verify as cpv

HERE = Path(__file__).resolve().parent
EXPECTED_AP = 'a3bffb09002988c4873122b6db41a2e23c87c2a66ff82a2d53b0fdb6959f533d'
EXPECTED_CP = '48ff01e346ac74e78b61f811725c0bd95ab2712938b55ad607a5b2f54a3bf4e1'
SOURCE_META, TARGET_META = 0x9108720, 0x9108708
MAPPING = menu.RAM + 0x5000
RANGES = [(0x3428510, 0x342863c), (0x342888c, 0x34289f0),
          (0x30210c8, 0x3021338), (0x3020430, 0x3020454),
          (0x301fadc, 0x301fb48), (0x34d37e8, 0x34d3868),
          (0x3552f54, 0x35530e4), (0x34cfac8, 0x34cfb08),
          (0x3537eac, 0x3537f58), (0x352c85c, 0x352c8a0)]
sha = lambda b: hashlib.sha256(b).hexdigest()


class Upload(menu.Native):
    def __init__(self, raw, payload, fault=None, special=False):
        super().__init__(raw)
        self.payload, self.fault, self.special = payload, fault, special
        self.timeline, self.paths, self.copies = [], [], []
        self.transfer = None
        self.put(SOURCE_META + 4, 0x101)
        self.write(SOURCE_META + 8, struct.pack('<Q', 0x70000000))
        self.put(SOURCE_META + 16, 0xc000)
        self.put(TARGET_META + 4, 0x202)
        self.write(MAPPING, b'\xdd' * 0xc000)
        if fault == 'missing_source': self.put(SOURCE_META + 4, 0)
        if fault == 'missing_target': self.put(TARGET_META + 4, 0)
        if fault == 'capacity': self.put(SOURCE_META + 16, 8)
        # errno storage is an isolated fixture for open/munmap/close errors.
        self.put(menu.RAM + 0x1f000, 5)

    def string(self, ptr):
        out = bytearray()
        for i in range(512):
            self.ensure(ptr + i, 1)
            c = self.u.mem_read(ptr + i, 1)[0]
            if not c: return bytes(out).decode('ascii')
            out.append(c)
        raise AssertionError('unterminated fixture string')

    def code(self, u, pc, size, data):
        x = [u.reg_read(menu.X(i)) for i in range(6)]
        if pc == 0x165ded0:
            assert self.string(x[2]) == '%s/LUT%03d.LUT'
            assert self.string(x[3]) == '/usr/data/lut' and x[1] == 26
            name = (self.string(x[3]) + '/LUT%03d.LUT' % x[4]).encode()
            self.write(x[0], name + b'\0'); self.ret(len(name)); return
        if pc == 0x165f990:
            assert self.string(x[1]) == 'r'
            self.paths.append(self.string(x[0])); self.timeline.append('fopen')
            self.ret(0 if self.fault == 'file_open' else 0x123); return
        if pc == 0x165f4e0:
            assert x[1] == 1 and x[2] == (0xbc00 if self.special else 0xc000) and x[3] == 0x123
            data = self.payload[:x[2]]
            self.write(x[0], data); self.timeline.append('fread_' + str(len(data)))
            self.ret(len(data)); return
        if pc == 0x165e800:
            assert x[0] == 0x123
            self.timeline.append('fclose'); self.ret(-1 & 0xffffffff if self.fault == 'file_close' else 0); return
        if pc == 0x16600c0:
            assert x[0] == 30
            self.ret(4096); return
        if pc == 0x165d3c0:
            assert self.string(x[0]) == '/dev/mem' and x[1] == 0x101002
            self.timeline.append('open_mapping')
            self.ret(0xffffffff if self.fault == 'map_open' else 12); return
        if pc == 0x165eba0:
            assert x == [0, self.word(SOURCE_META + 16), 3, 1, 12, 0x70000000]
            self.timeline.append('mmap')
            self.ret((1 << 64) - 1 if self.fault == 'mmap' else MAPPING); return
        if pc in (0x165d270, 0x165d3e0):
            dst, src, length = x[:3]
            # Catch MAP_FAILED use before allowing any host/emulated write.
            if dst == (1 << 64) - 1:
                self.timeline.append('invalid_map_destination')
                u.emu_stop(); return
            assert length <= 0xc000
            data = bytes([src & 255]) * length if pc == 0x165d270 else bytes(u.mem_read(src, length))
            self.write(dst, data)
            if dst == MAPPING:
                self.timeline.append('clear_shared' if pc == 0x165d270 else 'copy_shared')
                if pc == 0x165d3e0: self.copies.append(sha(data))
            self.ret(dst); return
        if pc == 0x165de10:
            assert x[:2] == [MAPPING, self.word(SOURCE_META + 16)]
            self.timeline.append('munmap')
            self.ret(0xffffffff if self.fault == 'munmap' else 0); return
        if pc == 0x165f430:
            assert x[0] == 12
            self.timeline.append('close_mapping')
            self.ret(0xffffffff if self.fault == 'map_close' else 0); return
        if pc == 0x165f050:
            self.ret(menu.RAM + 0x1f000); return
        if pc == 0x36804c8:
            self.ret(); return
        if pc == 0x34cb5e8:
            # Native implementation 3514f54 calls interchip_transfer_async,
            # then waits through 3514ae8. Its runtime is NOT executed here.
            self.transfer = struct.unpack('<6I', u.mem_read(x[0], 24))
            assert self.transfer == (0x101, 0, 0x202, 0, min(len(self.payload), 0xbc00 if self.special else 0xc000), 0)
            self.timeline.append('interchip_completion_fixture')
            self.put(x[1], 2 if self.fault == 'transfer' else 0)
            self.ret(); return
        if pc == 0x34c6418:
            self.timeline.append('secondary_setting_fixture'); self.ret(); return
        if pc == 0x35358b8:
            assert x[0] == 0x90030001 and x[2] == 0x60
            msg = bytes(u.mem_read(x[1], 0x60))
            assert struct.unpack_from('<H', msg, 2)[0] == 0x4155
            self.messages.append(msg); self.timeline.append('send_4155_fixture'); self.ret(); return
        super().code(u, pc, size, data)

    def upload(self, pp=12, lut=3, exists=1):
        self.task(0x311a63c, 2, pp, lut, exists)
        ptr = self.run(0x2887b48)
        self.write(ptr + lut - 3, bytes([int(self.special)]))
        # Getter returns a byte array, not a 32-bit element array. Only this
        # selected byte is meaningful to the native reader/descriptor builder.
        self.timeline.clear(); self.messages.clear()
        try:
            result = self.run(0x34289a8, (menu.RAM + 0x4000,), RANGES)
        except AssertionError:
            if self.fault != 'mmap' or self.timeline[-1] != 'invalid_map_destination': raise
            return None
        assert result == 1 and len(self.messages) == 1
        return self.messages[0]


def receive(cp, message, mapping_error=False):
    u = cpv.n.cp_machine(); u.mem_write(0x108000, cp)
    obj = 0x16596d0
    cpv.put(u, obj, 0xffffffff)
    cpv.put(u, cpv.G + 0xc0, 17)
    u.mem_write(cpv.G + 0x68, b'\xaa' * 0x57)
    u.mem_write(cpv.RAM, message)
    events = []
    def hook(u, pc, size, unused):
        r = [u.reg_read(cpv.reg(i)) for i in range(4)]
        def ret(v=0):
            u.reg_write(cpv.reg(0), v); u.reg_write(ar.UC_ARM_REG_PC, u.reg_read(ar.UC_ARM_REG_LR))
        if pc == 0xb44b96:
            assert r[:2] in ([obj, 5], [obj, 0xb5])
            events.append('mapping_release_fixture'); ret()
        elif pc == 0xb44a2c:
            assert r[:3] == [obj, 1, 5]
            events.append('mapping_acquire_fixture')
            if not mapping_error: u.mem_write(obj + 0x10, struct.pack('<Q', 0x71000000))
            ret(int(mapping_error))
        elif pc == 0x61ed00:
            u.mem_write(r[0], bytes(r[1])); ret()
        else: assert 0x35c54c <= pc < 0x35c694, hex(pc)
    u.hook_add(UC_HOOK_CODE, hook)
    saved = {cpv.reg(i): 0x11800000 + i for i in range(4, 12)}
    for reg, val in saved.items(): u.reg_write(reg, val)
    u.reg_write(cpv.reg(0), cpv.RAM)
    u.reg_write(ar.UC_ARM_REG_SP, cpv.SP); u.reg_write(ar.UC_ARM_REG_LR, cpv.STOP | 1)
    u.emu_start(0x35c54d, cpv.STOP, count=5000)
    assert u.reg_read(ar.UC_ARM_REG_PC) == cpv.STOP
    assert u.reg_read(ar.UC_ARM_REG_SP) == cpv.SP
    assert all(u.reg_read(reg) == val for reg, val in saved.items())
    assert cpv.word(u, cpv.G + 0xc0) == 18
    return {'descriptor': list(struct.unpack('<6I', u.mem_read(cpv.G + 0x68, 24))),
            'events': events, 'generation': 18,
            'context_hex': bytes(u.mem_read(cpv.G + 0x68, 96)).hex()}


def capture_boundary(cp, received):
    manifest = json.loads((HERE / 'dev-menu-02/manifest.json').read_text())
    c = cpv.Capture(cp, manifest)
    c.u.mem_write(cpv.G + 0x68, bytes.fromhex(received['context_hex']))
    # Request native acquisition/load, not a pre-declared ready result.
    cpv.put(c.u, cpv.STATE, 1)
    cpv.put(c.u, cpv.RES, 0x8833)
    return c.run()


def main():
    paths = [HERE / 'dev-menu-02/candidate' / n for n in ('appFw.so', 'cpapp-b.bin')]
    ap, cp = [p.read_bytes() for p in paths]
    assert (sha(ap), sha(cp)) == (EXPECTED_AP, EXPECTED_CP)
    # This is a byte-transfer fixture, not a valid color LUT or an image test.
    payload = bytes((i * 17 + 3) % 256 for i in range(0xbb80))
    cases = []
    for pp in range(12, 16):
        for lut in range(3, 19):
            h = Upload(ap, payload); message = h.upload(pp, lut)
            got = receive(cp, message)
            assert h.paths == ['/usr/data/lut/LUT%03d.LUT' % (lut - 2)]
            assert h.copies == [sha(payload)]
            assert got['descriptor'] == [0x71000000, 0, 0x71000000, 0, 0xbb80, 0]
            assert h.timeline.index('copy_shared') < h.timeline.index('munmap') < h.timeline.index('interchip_completion_fixture') < h.timeline.index('send_4155_fixture')
            cases.append({'pp': pp, 'lut': lut, 'path': h.paths[0], **got})
    failures = []
    for fault in ('file_open', 'empty', 'short', 'file_close', 'missing_source', 'missing_target', 'capacity', 'map_open', 'mmap', 'munmap', 'map_close', 'transfer'):
        data = b'' if fault == 'empty' else payload[:17] if fault == 'short' else payload
        h = Upload(ap, data, fault); message = h.upload()
        if fault == 'mmap':
            assert message is None and not h.messages and not h.copies
            failures.append({'case': fault, 'native_attempted_invalid_write': True, 'timeline': h.timeline}); continue
        got = receive(cp, message)
        accepted = fault in ('short', 'file_close')
        assert got['descriptor'] == ([0x71000000, 0, 0x71000000, 0, len(data), 0] if accepted else [0] * 6)
        failures.append({'case': fault, 'accepted': accepted, 'timeline': h.timeline, **got})
    h = Upload(ap, payload + bytes(128), special=True); message = h.upload(lut=18)
    got = receive(cp, message)
    assert got['descriptor'] == [0x71000000, 0, 0x71000000 + 48000, 0, 48000, 124]
    special = {'timeline': h.timeline, **got}
    special['capture'] = capture_boundary(cp, got)
    assert special['capture']['stops'] == ['0x54e398']
    hshort = Upload(ap, payload[:17], special=True)
    short_received = receive(cp, hshort.upload(lut=18))
    short_capture = capture_boundary(cp, short_received)
    assert short_received['descriptor'] == got['descriptor']
    assert short_capture['stops'] == ['0x54e398']
    short_special = {'uploaded_bytes': 17, 'advertised_bytes': 48124,
                     'timeline': hshort.timeline, 'capture': short_capture, **short_received}
    # A regular short read retains its actual size; the photo entry rejects it.
    hnormal = Upload(ap, payload[:17]); normal_received = receive(cp, hnormal.upload())
    normal_capture = capture_boundary(cp, normal_received)
    assert normal_capture.get('terminal') == '0x48c778' and normal_capture['error'] == '0xc17e0001'
    hvalid = Upload(ap, payload); valid_received = receive(cp, hvalid.upload())
    valid_capture = capture_boundary(cp, valid_received)
    assert valid_capture['stops'] == ['0x54e15c']
    length_cases = []
    for length in (1, 47999, 48000, 48123, 48124, 48128, 50000):
        raw_bytes = (payload + bytes(2000))[:length]
        hlen = Upload(ap, raw_bytes, special=True)
        received = receive(cp, hlen.upload())
        capture = capture_boundary(cp, received)
        assert received['descriptor'] == got['descriptor']
        assert capture['stops'] == ['0x54e398']
        length_cases.append({'file_bytes': length, 'uploaded_bytes': min(length, 48128),
                             'advertised_bytes': 48124, 'native_loader_entered': True,
                             'payload_shorter_than_descriptor': length < 48124})
    rejected = receive(cp, message, mapping_error=True)
    assert rejected['descriptor'] == [0] * 6
    h = Upload(ap, payload); message = h.upload(exists=0)
    absent = receive(cp, message)
    assert not h.paths and absent['descriptor'] == [0] * 6
    assert [sha(p.read_bytes()) for p in paths] == [EXPECTED_AP, EXPECTED_CP]
    report = {'status': 'OFFLINE_BOUNDARIES_ONLY', 'readiness': 'NOT_READY_TO_FLASH', 'camera_io': False,
              'ap_sha256': EXPECTED_AP, 'cp_sha256': EXPECTED_CP, 'script_sha256': sha(Path(__file__).read_bytes()),
              'source_hashes': {name: sha((HERE / name).read_bytes()) for name in
                                ('verify_lut_upload.py', 'verify_menu.py', 'verify.py', 'build.py')},
              'normal_cases': cases, 'fault_cases': failures, 'special_layout': special,
              'cp_mapping_failure': rejected, 'absent_slot': absent,
              'short_special_counterexample': short_special,
              'special_length_cases': length_cases,
              'regular_short_capture': normal_capture, 'regular_valid_capture': valid_capture,
              'boundaries': ['libc file and mmap services use in-memory fixtures', 'interchip completion is injected at 34cb5e8; async runtime not executed',
                             'CP shared-buffer mapping/ownership services are fixtures', 'no real LUT parser, pixels, MMIO, cache coherency, or concurrent scheduling tested']}
    (HERE / 'dev-menu-02/lut-upload-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'normal_cases': len(cases), 'fault_cases': len(failures), 'special_and_cp_cases': 6, 'special_length_cases': len(length_cases), 'readiness': report['readiness']}))


if __name__ == '__main__': main()
