"""Execute native menu gates and LUT task constructors from a local candidate.

Framework locks, object registration and menu lookup are explicit fixtures.
Native mode decisions, option bytes, getters, PP-link resolution and task
field construction execute real instructions. No camera modules are imported.
"""
import argparse
import io
import itertools
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as a
import build as b

RAM, STACK, STOP = 0x10000000, 0x10010000, 0x10020000
VTABLE, OPTIONS, PARAMETER = 0x597d578, 0x59b22b8, 0x5a115c8
X = lambda i: getattr(a, 'UC_ARM64_REG_X' + str(i))


class Native:
    def __init__(self, raw):
        self.raw = raw
        self.segments = [dict(s.header) for s in ELFFile(io.BytesIO(raw)).iter_segments() if s['p_type'] == 'PT_LOAD']
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.mapped = set()
        self.profile = 0
        self.feature_a2 = 0
        self.events = []
        self.allowed = []
        self.messages = []
        self.u.hook_add(UC_HOOK_MEM_UNMAPPED, self.unmapped)
        self.u.hook_add(UC_HOOK_CODE, self.code)
        self.ensure(RAM, 0x21000)
        self.write(RAM, struct.pack('<Q', VTABLE))
        self.write(RAM + 0x3000, struct.pack('<Q', PARAMETER))
        self.option_lookup = self.qword(VTABLE + 0x788)

    def ensure(self, address, size):
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            if page in self.mapped:
                continue
            matches = [s for s in self.segments if page < s['p_vaddr'] + s['p_memsz'] and page + 4096 > s['p_vaddr']]
            assert matches or RAM <= page < STOP + 4096, hex(page)
            assert page != 0, 'unexpected null dereference'
            self.u.mem_map(page, 4096)
            self.mapped.add(page)
            for s in matches:
                lo, hi = max(page, s['p_vaddr']), min(page + 4096, s['p_vaddr'] + s['p_filesz'])
                if hi > lo:
                    off = s['p_offset'] + lo - s['p_vaddr']
                    self.u.mem_write(lo, self.raw[off:off + hi - lo])

    def unmapped(self, u, access, address, size, value, data):
        self.ensure(address, size)
        return True

    def write(self, address, data):
        self.ensure(address, len(data))
        self.u.mem_write(address, data)

    def put(self, address, value):
        self.write(address, struct.pack('<I', value))

    def word(self, address):
        self.ensure(address, 4)
        return struct.unpack('<I', self.u.mem_read(address, 4))[0]

    def qword(self, address):
        self.ensure(address, 8)
        return struct.unpack('<Q', self.u.mem_read(address, 8))[0]

    def ret(self, value=0):
        self.u.reg_write(X(0), value)
        self.u.reg_write(a.UC_ARM64_REG_PC, self.u.reg_read(a.UC_ARM64_REG_LR))

    def code(self, u, address, size, data):
        if address == 0x251dd4c:
            self.write(u.reg_read(X(0)), struct.pack('<Q', RAM + 0x2000))
            self.events.append('fixture: model API object')
            self.ret()
            return
        if address == 0x178f950:
            self.write(u.reg_read(X(0)) + 8, struct.pack('<Q', RAM + 0x2000))
            self.events.append('fixture: model write lock')
            self.ret()
            return
        if address in (0x178f974, 0x251dd5c, 0x368312c, 0x36eb21c, 0x36eb3f0,
                       0x3683218, 0x36830a8, 0x2e01874, 0x2506ff0, 0x2506218):
            self.events.append('fixture: model framework boundary ' + hex(address))
            self.ret()
            return
        if address == 0x1b66d8c:
            self.events.append('fixture: normalize PP registry key')
            self.ret(0)
            return
        if address == 0x1b6e978:
            self.ret(1)
            return
        if address == 0x1b6e9d0:
            self.ret(RAM + 0x3000)
            return
        if address in (0x3683324, 0x36833e4, 0x36825d0):
            self.events.append('fixture: API trace/log boundary')
            self.ret()
            return
        if address == 0x35358b8:
            assert u.reg_read(X(0)) == 0x90030001 and u.reg_read(X(2)) == 16
            pointer = u.reg_read(X(1))
            self.messages.append(bytes(u.mem_read(pointer, 16)))
            self.events.append('fixture: AP transport captured, not transmitted')
            self.ret()
            return
        if address == 0x34c6498:
            self.events.append('fixture: secondary non-LUT setting boundary')
            self.ret()
            return
        if address in (0x2e06cc0, 0x2e068cc):
            self.events.append('fixture: model read lock/unlock')
            self.ret()
            return
        if address == self.option_lookup:
            assert u.reg_read(X(1)) == 0x807 + self.profile
            self.ret(OPTIONS + self.profile * 0xb8)
            return
        if address == 0x1b70ad0:
            self.events.append('fixture: option-to-parent registry lookup')
            self.ret(0)
            return
        if address == 0x1b59700:
            self.events.append('fixture: PP parameter registry lookup')
            self.ret(PARAMETER)
            return
        if address == 0x303dc60:
            self.events.append('fixture: sequence base constructor')
            self.ret()
            return
        if address == 0x352d794:
            self.events.append('fixture: task instance id')
            self.ret(1)
            return
        if address == 0x2e05298:
            assert u.reg_read(X(0)) == 0xa2
            self.events.append('fixture: feature flag 0xa2')
            self.ret(self.feature_a2)
            return
        if address == 0x1660080:
            dst, src, length = (u.reg_read(X(i)) for i in range(3))
            assert length == 64
            self.ensure(src, length)
            self.write(dst, bytes(u.mem_read(src, length)))
            self.events.append('fixture: bounded native string copy')
            self.ret(dst)
            return
        assert any(lo <= address < hi for lo, hi in self.allowed), 'unexpected call ' + hex(address)

    def run(self, entry, args=(), allowed=()):
        self.allowed = list(allowed) + [(0x2850000, 0x28a0000)]
        self.events = []
        for i, value in enumerate(args):
            self.u.reg_write(X(i), value)
        preserved = {X(i): 0x22220000 + i for i in range(19, 30)}
        for reg, value in preserved.items():
            self.u.reg_write(reg, value)
        self.u.reg_write(a.UC_ARM64_REG_SP, STACK + 0xff00)
        self.u.reg_write(a.UC_ARM64_REG_LR, STOP)
        self.ensure(entry, 4)
        self.u.emu_start(entry, STOP, count=5000)
        assert self.u.reg_read(a.UC_ARM64_REG_PC) == STOP
        assert self.u.reg_read(a.UC_ARM64_REG_SP) == STACK + 0xff00
        assert all(self.u.reg_read(reg) == value for reg, value in preserved.items())
        return self.u.reg_read(X(0))

    def model(self, getter, value, offset=0):
        ptr = self.run(getter)
        self.put(ptr + offset, value)
        return ptr

    def gate(self, profile, shooting, general=1):
        self.profile = profile
        self.model(0x2879804, general)
        self.model(0x2860080, shooting)
        return self.run(0x1b61fd4, (RAM, 0x807 + profile),
                        ((0x1b61f80, 0x1b620b0), (0x1b5e250, 0x1b5e398)))

    def context(self, system, log, pp, cinematic, look):
        return self.run(0x303de48, (system, log, pp, cinematic, look),
                        ((0x303de48, 0x303de98), (0x51a6d3c, 0x51a6d70)))

    def task(self, entry, system, pp, lut, exists, log=0, cinematic=1, commit_from_menu=False):
        self.model(0x285f040, system)
        self.model(0x2879804, int(system == 3))
        self.model(0x2860080, int(system == 3))
        self.model(0x286725c, log)
        self.model(0x286969c, pp)
        self.model(0x2868c24, cinematic)
        self.model(0x286dce8, 0)
        self.model(0x28696c4, 2)
        for i, getter in enumerate((0x288e3f0, 0x288e418, 0x288e440, 0x288e468)):
            self.model(getter, lut if i == pp - 12 else 3 + i)
        self.model(0x288e2d8, exists, (lut - 3) * 4)
        self.model(0x288e328, 0, (lut - 3) * 4)
        self.model(0x288e300, 0, (lut - 3) * 64)
        if commit_from_menu:
            self.menu_commit(pp)
        self.write(RAM + 0x4000, b'\xa5' * 0x80)
        self.run(entry, (RAM + 0x4000,),
                 ((0x311a63c, 0x311aaaC), (0x303dca0, 0x303de98),
                  (0x3105ce0, 0x3105dac), (0x51a6d3c, 0x51a6d70)))
        selected, present = ((0x18, 0x6c) if entry == 0x311a63c else (0x38, 0x34))
        return self.word(RAM + 0x4000 + selected), self.word(RAM + 0x4000 + present)

    def menu_commit(self, profile):
        self.profile = profile
        self.model(0x286969c, 0)
        metadata = self.run(0x28696b0)
        # No redirection to a shadow value in this fixture. The native setter
        # writes the actual model field and emits its original notifications.
        self.write(metadata + 8, b'\0' * 8)
        self.run(0x1c25dac, (0x807 + profile,),
                 ((0x1c25dac, 0x1c25dec), (0x1b6eb2c, 0x1b6eb5c),
                  (0x1b6ea8c, 0x1b6eb2c), (0x1b6dcb4, 0x1b6dce4),
                  (0x2570710, 0x25707a4), (0x2570650, 0x2570710),
                  (0x1b29b00, 0x1b29b34)))
        ptr = self.run(0x286969c)
        assert self.word(ptr) == profile
        return self.word(ptr)

    def send_base_task(self):
        self.messages = []
        self.run(0x343a3d8, (RAM + 0x4000,),
                 ((0x343a3d8, 0x343a4c4), (0x34cfa48, 0x34cfa88),
                  (0x3537fd0, 0x353806c), (0x352c5dc, 0x352c790),
                  (0x51a6d00, 0x51a6d70)))
        assert len(self.messages) == 1
        msg = self.messages[0]
        assert struct.unpack_from('<H', msg, 2)[0] == 0x4157
        return list(msg[8:13])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('folder', type=Path)
    args = p.parse_args()
    candidate = (args.folder / 'candidate/appFw.so').read_bytes()
    original = (b.BASE / 'appFw.so').read_bytes()
    assert b.sha(original) == b.HASHES['appFw.so']
    old, new = Native(original), Native(candidate)
    report = {'status': 'MENU_AND_SETTING_COMPONENT_VERIFIED_NOT_RELEASE_READY', 'camera_io': False,
              'candidate_sha256': b.sha(candidate), 'menu_gates': [], 'context_cases': 0,
              'task_cases': [], 'task_to_ap_message': [], 'menu_commit_cases': []}
    for pp, shooting, general in itertools.product(range(16), (0, 1), (0, 1)):
        before, after = old.gate(pp, shooting, general), new.gate(pp, shooting, general)
        assert before == int(pp < 12 or (general == 1 and shooting == 1)), (pp, shooting, general, before)
        assert after == 1, (pp, shooting, after)
        report['menu_gates'].append({'profile': pp, 'general_shooting_mode': general,
                                    'secondary_mode': shooting, 'baseline': before, 'candidate': after})
    for system, log, pp, cinematic, look in itertools.product(range(8), (0, 1, 2), (0, 11, 12, 15, 16), (0, 1), (0, 6, 21, 22)):
        before = old.context(system, log, pp, cinematic, look)
        after = new.context(system, log, pp, cinematic, look)
        expected = int(log == 0 and 12 <= pp <= 15 and cinematic == 1) if system == 2 else before
        assert after == expected, (system, log, pp, cinematic, look, before, after)
        report['context_cases'] += 1
    for pp in range(16):
        report['menu_commit_cases'].append({'menu_value': hex(0x807 + pp),
                                            'actual_model_value': new.menu_commit(pp)})
    for entry, pp, lut, exists in itertools.product((0x311a63c, 0x311a88c), range(12, 16), range(3, 19), (0, 1)):
        before = old.task(entry, 2, pp, lut, exists)
        integrated_menu = entry == 0x311a88c and exists == 1
        after = new.task(entry, 2, pp, lut, exists, commit_from_menu=integrated_menu)
        assert before == (0, 0), (hex(entry), before)
        assert after == (lut, exists), (hex(entry), pp, lut, exists, after)
        report['task_cases'].append({'constructor': hex(entry), 'profile': pp, 'lut': lut,
                                     'registered': exists, 'baseline': before, 'candidate': after})
        if entry == 0x311a88c and exists:
            before_msg, after_msg = old.send_base_task(), new.send_base_task()
            assert before_msg[:2] == [11, 3], before_msg
            assert after_msg == [10, 0, 0, 1, 0], after_msg
            report['task_to_ap_message'].append({'profile': pp, 'lut': lut,
                                                'native_menu_confirm_to_model_executed': integrated_menu,
                                                'baseline': before_msg, 'candidate': after_msg})
    report['boundaries'] = {
        'executed': ['native still/movie option gate', 'native model getters', 'native PPLUT link resolver',
                     'native menu-value conversion, confirm handler and model setter',
                     'native upload-task constructor', 'native picture-setting task constructor',
                     'native picture-setting task executor and 4157 sender'],
        'fixtures': ['read locks', 'menu registry lookup', 'base object constructor', 'task id', 'feature flag',
                     'string copy', 'AP transport capture', 'secondary non-LUT settings',
                     'model registry and notification framework'],
        'not_proven': ['full menu event dispatch', 'model constraint recomputation', 'notification scheduling',
                       'mode transition persistence', 'actual LUT upload', 'resource recovery', 'camera JPEG'],
    }
    report['script_sha256'] = b.sha(Path(__file__).read_bytes())
    (args.folder / 'menu-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'menu_cases': len(report['menu_gates']),
                      'context_cases': report['context_cases'], 'native_task_cases': len(report['task_cases']),
                      'native_menu_commit_cases': len(report['menu_commit_cases']),
                      'native_task_to_ap_message_cases': len(report['task_to_ap_message'])}, indent=2))


if __name__ == '__main__':
    main()
