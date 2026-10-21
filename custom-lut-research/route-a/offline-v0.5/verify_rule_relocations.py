"""Run native rule evaluation after applying ELF relative relocations.

Only the rule evaluator is executed. This is not a replacement for Sony's
dynamic loader or a full AP boot test.
"""
import argparse
import io
import itertools
import json
import struct
from pathlib import Path

import numpy as np
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as a
import build as b
from verify_menu import RAM, STACK, STOP, X


class Relocated:
    def __init__(self, raw, bias):
        self.raw, self.bias = raw, bias
        elf = ELFFile(io.BytesIO(raw))
        self.segments = [dict(s.header) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        self.rela = np.frombuffer(elf.get_section_by_name('.rela.dyn').data(),
                                  dtype=[('offset', '<u8'), ('info', '<u8'), ('addend', '<i8')])
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.mapped, self.relocated = set(), set()
        self.u.hook_add(UC_HOOK_MEM_UNMAPPED, self.unmapped)
        self.u.hook_add(UC_HOOK_CODE, self.code)
        self.ensure(RAM, 0x21000)
        table = self.qword(bias + 0x5b66c10)
        records = self.qword(table + 0x3f5 * 16)
        for i in range(self.word(table + 0x3f5 * 16 + 8)):
            rec = self.qword(records + i * 8)
            source = self.word(rec + 12)
            self.put(bias + 0x7e340d0 + source * 24 + 8, 0x80000000)

    def ensure(self, address, size):
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            if page in self.mapped:
                continue
            relative = page - self.bias
            matches = [s for s in self.segments if relative < s['p_vaddr'] + s['p_memsz']
                       and relative + 4096 > s['p_vaddr']]
            assert matches or RAM <= page < STOP + 4096, hex(page)
            self.u.mem_map(page, 4096)
            self.mapped.add(page)
            for s in matches:
                lo, hi = max(relative, s['p_vaddr']), min(relative + 4096, s['p_vaddr'] + s['p_filesz'])
                if hi > lo:
                    off = s['p_offset'] + lo - s['p_vaddr']
                    self.u.mem_write(lo + self.bias, self.raw[off:off + hi - lo])
            if matches:
                for r in self.rela[(self.rela['offset'] >= relative) & (self.rela['offset'] < relative + 4096)]:
                    offset, info, addend = int(r['offset']), int(r['info']), int(r['addend'])
                    assert offset + 8 <= relative + 4096
                    if info == 1027:
                        self.u.mem_write(offset + self.bias, struct.pack('<Q', addend + self.bias))
                        self.relocated.add(offset)
                    else:
                        # Unresolved external relocation: poison it so an
                        # accidental dependency fails instead of using stale VA.
                        self.u.mem_write(offset + self.bias, b'\xfe' * 8)

    def unmapped(self, u, access, address, size, value, data):
        self.ensure(address, size)
        return True

    def code(self, u, address, size, data):
        relative = address - self.bias
        assert 0x247154c <= relative < 0x247192c or 0x246e814 <= relative < 0x246ea2c, hex(address)

    def write(self, address, raw):
        self.ensure(address, len(raw))
        self.u.mem_write(address, raw)

    def put(self, address, value):
        self.write(address, struct.pack('<I', value))

    def word(self, address):
        self.ensure(address, 4)
        return struct.unpack('<I', self.u.mem_read(address, 4))[0]

    def qword(self, address):
        self.ensure(address, 8)
        return struct.unpack('<Q', self.u.mem_read(address, 8))[0]

    def evaluate(self, exposure, value):
        self.put(self.bias + 0x7e340d0 + 0x14d * 24 + 8, exposure)
        self.write(RAM + 0x6000, struct.pack('<6I', 0x3f5, value, value, value, 0, 0))
        self.put(RAM + 0x6100, value)
        self.put(RAM + 0x6200, 0)
        for i, val in enumerate((RAM + 0x7000, RAM + 0x6000, RAM + 0x6100, RAM + 0x6200, 0)):
            self.u.reg_write(X(i), val)
        preserved = {X(i): 0x22220000 + i for i in range(19, 30)}
        for reg, val in preserved.items():
            self.u.reg_write(reg, val)
        self.u.reg_write(a.UC_ARM64_REG_SP, STACK + 0xff00)
        self.u.reg_write(a.UC_ARM64_REG_LR, STOP)
        self.u.emu_start(self.bias + 0x247154c, STOP, count=10000)
        assert self.u.reg_read(a.UC_ARM64_REG_PC) == STOP
        assert self.u.reg_read(a.UC_ARM64_REG_SP) == STACK + 0xff00
        assert all(self.u.reg_read(reg) == val for reg, val in preserved.items())
        return self.word(RAM + 0x6100)


def main(folder):
    paths = {'before': b.HERE / 'dev-menu-01/candidate/appFw.so',
             'after': folder / 'candidate/appFw.so'}
    cases = []
    for label, path in paths.items():
        raw = path.read_bytes()
        for bias in (0x100000000, 0x7100000000):
            n = Relocated(raw, bias)
            count = 0
            for exposure, value in itertools.product(range(0x172c, 0x1730), range(0x3115, 0x3126)):
                result = n.evaluate(exposure, value)
                expected = value
                if label == 'before' and 0x3121 <= value <= 0x3124 or exposure == 0x172c and value == 0x3125:
                    expected = 0x3115
                assert result == expected, (label, hex(bias), hex(exposure), hex(value), hex(result))
                count += 1
            assert 0x5245e00 in n.relocated
            assert n.qword(bias + 0x5245e00) == bias + (0x422bbf0 if label == 'before' else 0x422bc20)
            cases.append({'image': label, 'bias': hex(bias), 'cases': count,
                          'relative_relocations_applied_on_accessed_pages': len(n.relocated)})
    report = {'camera_io': False, 'cases': cases, 'native_evaluator_cases': sum(r['cases'] for r in cases),
              'sha256': {k: b.sha(p.read_bytes()) for k, p in paths.items()},
              'scope': 'Native evaluator, two nonzero load biases, actual R_AARCH64_RELATIVE addends; no dynamic linker or AP boot execution.',
              'source_sha256': b.sha(Path(__file__).read_bytes())}
    (folder / 'menu-relocation-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'native_evaluator_cases': report['native_evaluator_cases']}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    main(parser.parse_args().folder)
