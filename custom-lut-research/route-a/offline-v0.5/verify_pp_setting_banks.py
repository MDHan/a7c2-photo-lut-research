"""Native PP confirmation -> alias notification -> dirty bits -> Backup worker.

The parent's separate exclusion queue is deliberately left pending. This is
evidence for the two setting banks, not the complete menu/event loop or boot.
"""
import json
import struct
from pathlib import Path

from install_transaction import digest
from verify_menu import Native, RAM
from verify_settings_commit import Commit, ALLOWED, DIRTY, QUEUE

HERE = Path(__file__).resolve().parent
EXTRA = ((0x2506fbc, 0x25070d0), (0x24cbeac, 0x24cbee4),
         (0x2491708, 0x249175c), (0x28bb090, 0x28bb140),
         (0x27f70cc, 0x27f70d4), (0x27fbf0c, 0x27fbf1c),
         (0x2775e8c, 0x2775ec8), (0x278c7bc, 0x278c834),
         (0x2e09a40, 0x2e09a50), (0x2e09604, 0x2e0963c),
         (0x24cb278, 0x24cb2d4), (0x2490e18, 0x2490e9c),
         (0x2f3b170, 0x2f3b250), (0x2f39a20, 0x2f39a58),
         (0x2e31e84, 0x2e31ed8), (0x2a26a9c, 0x2a26aa0), (0x2a26a14, 0x2a26a18))
MENU = ((0x1c25dac, 0x1c25dec), (0x1b6eb2c, 0x1b6eb5c),
        (0x1b6ea8c, 0x1b6eb2c), (0x1b6dcb4, 0x1b6dce4),
        (0x2570710, 0x25707a4), (0x2570650, 0x2570710),
        (0x1b29b00, 0x1b29b34))


class Banks(Commit):
    def __init__(self, raw):
        super().__init__(raw, (0x57b9468, 0x57b9488, 0x57be7c8, 0x57be7e8))
        aliases = [raw[o:o+24] for o in range(0x4b93360, 0x4b95358, 24)]
        assert len(aliases) == 341
        assert [struct.unpack('<6I', r) for r in aliases if struct.unpack_from('<I', r)[0] == 0x66d] == [
            (0x66d, 0x66d, 0x1035, 0x1036, 1, 8)]
        self.hashmap(0x88387d0, aliases, RAM + 0x11000, bucket_count=17)
        deferred = [raw[o:o+8] for o in range(0x4ba17a0, 0x4ba17b0, 8)]
        self.hashmap(0x88bad50, deferred, RAM + 0x14000)
        self.write(0x7e4e630, bytes(0x50))
        for offset, value in [(0x10, RAM+0x16000), (0x18, RAM+0x16000), (0x20, RAM+0x16200),
                              (0x30, RAM+0x16000), (0x38, RAM+0x16000), (0x40, RAM+0x16200)]:
            self.write(0x7e4e630+offset, struct.pack('<Q', value))

    def run(self, entry, args=(), allowed=()):
        return super().run(entry, args, tuple(allowed) + EXTRA + ALLOWED)

    def code(self, u, address, size, data):
        if address == 0x2506ff0:
            assert any(lo <= address < hi for lo, hi in self.allowed)
            return  # execute original notification; override Native fixture
        if address in (0x2e017c4, 0x2d8dd84, 0x2e0af7c):
            self.events.append('fixture: non-storage secondary notification ' + hex(address))
            self.ret()
            return
        super().code(u, address, size, data)

    def exercise(self, pp, split, general, shooting):
        self.profile = pp
        self.model(0x285cff0, split)
        self.model(0x2879804, general)
        self.model(0x2860080, shooting)
        self.put(0x7e705f0, 0)
        self.put(0x7e705f8, 0)
        self.write(0x7e70600, struct.pack('<Q', 0x7e705f8))
        self.put(0x7e83cf0, 1)
        self.put(0x7e83cf8, 1)
        self.put(0x7e83d20, 2)
        self.put(0x7e83d28, 2)
        self.write(DIRTY, bytes(0x930))
        self.put(0x8838b40, 1)
        for r, value in zip(self.records, (0, 7, 1, 2)):
            self.write(r[7], bytes([value]) + bytes(3))
            self.storage[r[3]] = bytes([value])
        self.run(0x1c25dac, (0x807+pp,), MENU)
        still = general == 0 or shooting == 0
        expected_banks = (pp if not split or still else 1, pp if not split or not still else 2)
        assert self.word(0x7e705f0) == self.word(0x7e705f8) == pp
        assert (self.word(0x7e83cf0), self.word(0x7e83d20)) == expected_banks
        assert (self.word(0x7e83cf8), self.word(0x7e83d28)) == expected_banks
        expected_dirty = [0x1035+i for i, (v, old) in enumerate(zip(expected_banks, (1, 2))) if v != old]
        actual_dirty = [mid for mid in range(0x930*8)
                        if self.u.mem_read(DIRTY+mid//8, 1)[0] & (1 << (mid%8))]
        assert actual_dirty == expected_dirty
        assert self.qword(0x7e4e660) == RAM+0x16004  # parent PP queued exactly once
        assert self.word(RAM+0x16000) == 0x66d
        self.run(0x2f3a11c, allowed=ALLOWED)
        self.consume()
        expected_writes = [{'subsystem': 0x2cf, 'key': r[3], 'bytes': bytes([v]).hex()}
                           for r, v, old in zip(self.records[2:], expected_banks, (1, 2)) if v != old]
        assert self.backup_calls == expected_writes
        return {'pp': pp, 'split': split, 'general_mode': general, 'shooting_mode': shooting,
                'bank_values': expected_banks, 'native_dirty_ids': actual_dirty,
                'backup_write_calls': self.backup_calls, 'parent_exclusion_queue_still_pending': True}


def main():
    raw = (HERE / 'dev-menu-02/candidate/appFw.so').read_bytes()
    cases = [Banks(raw).exercise(pp, split, general, shooting)
             for pp in (12, 13, 14, 15) for split in (0, 1)
             for general, shooting in ((0, 0), (1, 1), (0, 1), (1, 0))]
    report = {'status': 'PP_ALIAS_BANK_NOTIFICATION_TO_BACKUP_BOUNDARY_VERIFIED',
              'camera_io': False, 'candidate_flash_ready': False, 'ap_sha256': digest(raw),
              'sources': {n: digest((HERE/n).read_bytes()) for n in
                          ('verify_pp_setting_banks.py', 'verify_settings_commit.py', 'verify_menu.py', 'build.py')},
              'cases': cases, 'case_count': len(cases),
              'alias_row_file_offset': 0x4b93438,
              'bank_model_ids': [0x1035, 0x1036], 'bank_storage_keys': [0x02cf0e10, 0x02cf0e12],
              'fixtures': ['Runtime containers populated from actual static rows',
                           'Registry menu lookup, locks, logging and secondary non-storage notification',
                           'Backup service captured, never invoked on a camera'],
              'not_verified': ['Parent PP exclusion queue drain and full event loop',
                               'Mode transition loading selected bank back into active PP',
                               'Cold boot/MR and actual storage persistence',
                               'LUT linkage/upload and CP resource lifecycle']}
    (HERE/'dev-menu-02/pp-setting-bank-verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'status': report['status'], 'camera_io': False, 'cases': len(cases)}, indent=2))


if __name__ == '__main__':
    main()
