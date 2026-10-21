"""Offline native PP queue drain with explicit synthetic manager state."""
import json
import struct
from pathlib import Path
from unicorn import arm64_const as a

from install_transaction import digest
from verify_menu import RAM, STACK, STOP, X
from verify_pp_setting_banks import Banks, EXTRA, MENU
from verify_settings_commit import ALLOWED as STORAGE, DIRTY
from verify_dynamic_menu import ALLOWED as RULES, PP, EXPOSURE, STATES, COUNTERS

HERE = Path(__file__).resolve().parent
HEAP, MANAGER, ACCESSOR = 0x20000000, 0x20000000, 0x20000100
QUEUE_CODE = ((0x24cb320, 0x24cb494), (0x246e814, 0x2471d44),
              (0x3680b30, 0x3680b64), (0x2775ebc, 0x2775ec8),
              (0x2506054, 0x2506e30), (0x28bb140, 0x28bb17c), (0x25079f4, 0x2507b6c))


class Drain(Banks):
    def ensure(self, address, size):
        if HEAP <= address and address + size <= HEAP + 0x200000:
            for page in range(address & ~4095, (address+size+4095) & ~4095, 4096):
                if page not in self.mapped:
                    self.u.mem_map(page, 4096)
                    self.mapped.add(page)
            return
        super().ensure(address, size)

    def __init__(self, raw):
        super().__init__(raw)
        self.rule_calls, self.published, self.non_pp_inhibit_callbacks = 0, [], 0
        self.write(MANAGER, bytes(0x100))
        self.write(MANAGER, struct.pack('<Q', ACCESSOR))
        self.write(ACCESSOR, struct.pack('<Q', 0x5b2c088))
        self.write(0x7e4dc68, struct.pack('<Q', MANAGER))
        self.write(MANAGER+0x60, struct.pack('<QQQ', HEAP+0x2000, HEAP+0x2000, HEAP+0x4000))
        self.write(MANAGER+0x48, struct.pack('<QQQ', HEAP+0x4000, HEAP+0x4000, HEAP+0x5000))
        self.hashmap(MANAGER+0x10, [], HEAP+0x5000)
        # Real mapping records, reconstructed in a native hash container.
        rows = [raw[o:o+8] for o in range(0x41dc440, 0x41e06f8, 8)]
        assert len(rows) == 2135
        assert struct.pack('<II', 0x66d, PP) in rows
        self.hashmap(self.qword(0x5b52f58), rows, HEAP+0x10000, bucket_count=257)
        # Parameter-to-enum lookup required for PP. Its pairs are derived from
        # the native value descriptor table, not a substituted conversion call.
        table = self.qword(0x5b92788)
        enum_rows = [struct.pack('<II', self.word(table+v*8+4), v) for v in range(0x3115, 0x3126)]
        self.hashmap(self.qword(0x5b76a20), [struct.pack('<II', 0x66d, 0)+bytes(0x38)], HEAP+0x20000)
        self.hashmap(HEAP+0x20000+8+16, enum_rows, HEAP+0x21000, bucket_count=17)
        reverse_rows = [raw[o:o+8] for o in range(0x4b968a8, 0x4b97df8, 8)]
        assert len(reverse_rows) == 682
        assert not any(struct.unpack_from('<I', row)[0] == 0x66d for row in reverse_rows)
        self.hashmap(self.qword(0x5bb24b8), reverse_rows, HEAP+0x22000, bucket_count=97)
        # Observer lists are not initialized; model alias records are real.
        self.write(0x7e4e740, bytes(24))
        self.write(0x7e4e6c0, bytes(24))
        self.write(0x7e4e608, bytes(1))
        self.write(0x7e4e5e8, bytes(1))
        self.write(self.run(0x2862698), bytes(1))
        self.write(0x7e4e658, struct.pack('<Q', RAM+0x16500))
        self.write(0x7e4e678, struct.pack('<Q', RAM+0x16500))
        self.write(RAM+0x16500, struct.pack('<Q', RAM+0x16000))
        for mid in range(4270):
            self.write(STATES+mid*24, struct.pack('<4I8x', mid, 0x80000000, 0x80000000, 0x80000000))
        for value in range(0x3115, 0x3126):
            self.put(COUNTERS+value*4, 0)

    def code(self, u, address, size, data):
        if address == 0x246f158 and u.reg_read(X(1)) != PP:
            # Keep native reference counting (0x246f404) intact, including
            # underflow assertions. Other models' UI callback writes are an
            # explicit boundary, not replaced by forced counter values.
            self.non_pp_inhibit_callbacks += 1
            self.ret()
            return
        if address == 0x247192c:
            self.rule_calls += 1
        if address == 0x2470f14:
            row = u.reg_read(X(1))
            self.published.append((self.word(row), self.word(row+8)))
        if address == 0x3682ac4:
            self.ret(0)  # trace object only
            return
        if address in (0x3681e44, 0x3682148, 0x3682018):
            self.ret()
            return
        super().code(u, address, size, data)

    def run(self, entry, args=(), allowed=()):
        self.allowed = list(allowed) + list(EXTRA+STORAGE+RULES+QUEUE_CODE) + [(0x2850000, 0x28a0000)]
        self.events = []
        for i, value in enumerate(args):
            self.u.reg_write(X(i), value)
        preserved = {X(i): 0x22220000+i for i in range(19, 30)}
        for reg, value in preserved.items():
            self.u.reg_write(reg, value)
        self.u.reg_write(a.UC_ARM64_REG_SP, STACK+0xff00)
        self.u.reg_write(a.UC_ARM64_REG_LR, STOP)
        self.ensure(entry, 4)
        self.u.emu_start(entry, STOP, count=2000000)
        assert self.u.reg_read(a.UC_ARM64_REG_PC) == STOP, hex(self.u.reg_read(a.UC_ARM64_REG_PC))
        assert self.u.reg_read(a.UC_ARM64_REG_SP) == STACK+0xff00
        assert all(self.u.reg_read(reg) == value for reg, value in preserved.items())
        return self.u.reg_read(X(0))

    def choose_and_drain(self, profile, exposure, extra_constraint=False, restore_bank=False):
        self.profile = profile
        self.model(0x285cff0, 1)
        self.model(0x2879804, 0)
        self.model(0x2860080, 0)
        self.model(0x285f040, 2)
        initial_pp, initial_bank = (2, profile) if restore_bank else (0, 1)
        for at, value in [(0x7e705f0, initial_pp), (0x7e705f8, initial_pp), (0x7e83cf0, initial_bank),
                          (0x7e83cf8, initial_bank), (0x7e83d20, 2), (0x7e83d28, 2)]:
            self.put(at, value)
        self.write(0x7e70600, struct.pack('<Q', 0x7e705f8))
        self.put(0x8838b40, 1)
        self.write(DIRTY, bytes(0x930))
        for r, value in zip(self.records, (initial_pp, 7, initial_bank, 2)):
            self.write(r[7], bytes([value])+bytes(3))
            self.storage[r[3]] = bytes([value])
        # Existing PP OFF and chosen exposure are input fixtures. Other
        # parameters are UNKNOWN, not a complete valid camera snapshot.
        initial_enum = 0x3115+initial_pp
        self.write(STATES+PP*24, struct.pack('<4I8x', PP, initial_enum, initial_enum, initial_enum))
        self.write(STATES+EXPOSURE*24, struct.pack('<4I8x', EXPOSURE, exposure, exposure, exposure))
        initial = [(PP, initial_enum), (EXPOSURE, exposure)]
        if extra_constraint:
            self.write(STATES+0x11e*24, struct.pack('<4I8x', 0x11e, 0x15d2, 0x15d2, 0x15d2))
            initial.append((0x11e, 0x15d2))
        for source, value in initial:
            self.put(HEAP+0x6000, source)
            self.put(HEAP+0x6004, value)
            self.run(0x246f54c, (MANAGER, HEAP+0x6000, HEAP+0x6004, 1))
        if restore_bank:
            # Exact static PP alias row +4, as passed by the native full
            # mode-switch iterator at 0x2507c78. Invoke this PP helper only;
            # the other 340 aliases/full switch driver are outside this test.
            self.run(0x25079f4, (0x4b9343c, 1))
        else:
            self.run(0x1c25dac, (0x807+profile,), MENU)
        assert self.word(RAM+0x16000) == 0x66d
        self.run(0x24cb320)
        assert self.qword(0x7e4e640) == self.qword(0x7e4e660)
        assert self.rule_calls == 1
        result = {'requested_profile': profile, 'exposure': exposure,
                  'extra_constraint': extra_constraint,
                  'trigger': 'native_photo_bank_restore_helper' if restore_bank else 'native_menu_confirmation',
                  'active_profile_after_queue': self.word(0x7e705f0),
                  'requested_metadata_after_queue': self.word(0x7e705f8),
                  'banks': [self.word(0x7e83cf0), self.word(0x7e83d20)],
                  'published': self.published, 'rule_calls': self.rule_calls,
                  'non_pp_inhibit_callback_boundaries': self.non_pp_inhibit_callbacks}
        assert result['requested_metadata_after_queue'] == profile
        assert result['banks'] == [profile, 2]
        self.run(0x2f3a11c)
        self.consume()
        expected_calls = [{'subsystem': 0x2cf, 'key': 0x02cf0053, 'bytes': bytes([profile]).hex()}]
        if not restore_bank:
            expected_calls.append({'subsystem': 0x2cf, 'key': 0x02cf0e10, 'bytes': bytes([profile]).hex()})
        assert self.backup_calls == expected_calls
        result['backup_write_calls_after_queue'] = self.backup_calls
        return result


def main():
    names = ('verify_pp_exclusion_queue.py', 'verify_pp_setting_banks.py', 'verify_settings_commit.py',
             'verify_dynamic_menu.py', 'verify_menu.py', 'build.py')
    sources = {n: digest((HERE/n).read_bytes()) for n in names}
    images = {name: (HERE/name/'candidate/appFw.so').read_bytes() for name in ('dev-menu-01', 'dev-menu-02')}
    cases = []
    for name, raw in images.items():
        for exposure in range(0x172c, 0x1730):
            for profile in range(12, 16):
                result = Drain(raw).choose_and_drain(profile, exposure)
                assert result['active_profile_after_queue'] == (0 if name == 'dev-menu-01' else profile)
                cases.append({'image': name, **result})
    for profile in range(12, 16):
        result = Drain(images['dev-menu-02']).choose_and_drain(profile, 0x172c, extra_constraint=True)
        assert result['active_profile_after_queue'] == 0
        cases.append({'image': 'dev-menu-02', **result})
    for name, raw in images.items():
        for profile in range(12, 16):
            result = Drain(raw).choose_and_drain(profile, 0x172c, restore_bank=True)
            assert result['active_profile_after_queue'] == (0 if name == 'dev-menu-01' else profile)
            cases.append({'image': name, **result})
    assert sources == {n: digest((HERE/n).read_bytes()) for n in names}
    report = {'status': 'NATIVE_PP_QUEUE_DRAIN_AND_POST_CONSTRAINT_COMMIT_VERIFIED_WITH_FIXTURES',
              'camera_io': False, 'candidate_flash_ready': False, 'case_count': len(cases), 'cases': cases,
              'ap_sha256': {n: digest(raw) for n, raw in images.items()},
              'sources': sources,
              'executed': ['Menu confirmation and original PP bank notification',
                           '0x24cb320 actual pending-PP queue consumption',
                           '0x24707fc model-to-rule input conversion',
                           '0x247192c native manager loop over all 4270 rule-state rows',
                           'Original evaluation, reference counts and active-model writeback',
                           'Native PP photo-bank restore helper 0x25079f4 before queue processing',
                           'Native commit and Backup worker after the queue has drained'],
              'fixtures': ['Only PP/exposure (and one optional constraint) have concrete rule states; others UNKNOWN',
                           'Runtime hash containers rebuilt from static descriptors; PP enum conversion only',
                           'Non-PP inhibition UI callbacks intercepted after native counter update',
                           'Complete 682-row reverse alias map rebuilt; observer lists empty',
                           'Locks, tracing, menu lookup, secondary notifications and Backup service'],
              'not_verified': ['Complete camera initialization or simultaneous full parameter state',
                               'Complete observer/event scheduling and full mode-switch driver/all aliases',
                               'Cold boot/MR, LUT import/upload or actual nonvolatile writes',
                               'CP resources and native camera installation']}
    (HERE/'dev-menu-02/pp-exclusion-queue-verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k: report[k] for k in ('status', 'camera_io', 'case_count')}, indent=2))


if __name__ == '__main__':
    main()
