"""Native model commit -> native queue -> worker -> captured Backup_write.

No camera import or device I/O. Locks, libc, logging and the external Backup
service are fixtures. Runtime containers are populated from real ELF rows;
their C++ constructors and the upstream dirty-notification chain are not run.
"""
import io
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as a

from install_transaction import digest
from verify_menu import Native, RAM, STACK, STOP, X

HERE = Path(__file__).resolve().parent
MAP, CONVERSION, QUEUE, DIRTY = 0x8838b08, 0x8838808, 0x8838aa8, 0x88540d0
ROWS = (0x57b9468, 0x57b9488)
ALLOWED = ((0x2f3a11c, 0x2f3a48c), (0x2ae0070, 0x2ae008c),
           (0x2a7759c, 0x2a775b0), (0x2a77634, 0x2a77648),
           (0x2ecd738, 0x2ecd77c), (0x2e31e30, 0x2e31e84),
           (0x2e8cb5c, 0x2e8cb70), (0x2e90554, 0x2e9057c),
           (0x2e902fc, 0x2e90388), (0x2e0aab0, 0x2e0aafc),
           (0x2e0a8d8, 0x2e0a92c), (0x2ff07ac, 0x2ff0b30),
           (0x2f3a954, 0x2f3a99c), (0x35aa890, 0x35aa8a0))


class Commit(Native):
    def __init__(self, raw, row_offsets=ROWS):
        self.backup_calls, self.memcopies = [], []
        self.backup_reads, self.storage, self.allocations = [], {}, set()
        self.heap, self.read_count_override = RAM + 0xe000, None
        self.worker, self.stop_on_empty = False, False
        super().__init__(raw)
        self.rows = [raw[o:o+32] for o in row_offsets]
        self.records = [struct.unpack('<IIIIHHIQ', row) for row in self.rows]
        assert [(r[0], r[3], r[5]) for r in self.records[:2]] == [(0x66d, 0x02cf0053, 1), (0x66e, 0x02cf102d, 1)]
        self.hashmap(MAP, self.rows, RAM + 0x9000)
        conversion_rows = [raw[o:o+8] for o in range(0x4b97f48, 0x4b98480, 8)]
        assert len(conversion_rows) == 167
        assert not {r[3] for r in self.records} & {struct.unpack_from('<I', r)[0] for r in conversion_rows}
        self.hashmap(CONVERSION, conversion_rows, RAM + 0xa000)
        self.hashmap(0x8854a40, [], RAM + 0xc000)
        self.write(0x88bad48, struct.pack('<Q', RAM))
        self.put(RAM + 0x66e8, 0)  # normal map path, not attribute map
        self.write(0x88bad29, b'\0')
        self.write(0x88d92d1, b'\0')
        self.write(QUEUE, bytes(0x50))
        for offset, value in [(0x10, RAM+0xd000), (0x18, RAM+0xd000), (0x20, RAM+0xd200),
                              (0x30, RAM+0xd000), (0x38, RAM+0xd000), (0x40, RAM+0xd200)]:
            self.write(QUEUE+offset, struct.pack('<Q', value))

    def hashmap(self, address, rows, memory, bucket_count=1):
        # Native-compatible bucket groups and linked list. Each bucket points
        # at its first node's predecessor, not directly at the first node.
        rows = sorted(rows, key=lambda r: struct.unpack_from('<I', r)[0] % bucket_count)
        self.write(address, bytes(0x38))
        cursor = memory + 8*bucket_count
        self.write(address, struct.pack('<QQQQ', memory, bucket_count, cursor if rows else 0, len(rows)))
        self.write(memory, bytes(8*bucket_count))
        previous, seen = address+0x10, set()
        for i, row in enumerate(rows):
            bucket = struct.unpack_from('<I', row)[0] % bucket_count
            if bucket not in seen:
                self.write(memory+bucket*8, struct.pack('<Q', previous))
                seen.add(bucket)
            next_node = cursor + 8 + len(row) if i+1 < len(rows) else 0
            self.write(cursor, struct.pack('<Q', next_node) + row)
            previous = cursor
            cursor += 8 + len(row)

    def code(self, u, address, size, data):
        if self.worker and address == 0x2ff07ec:
            if self.qword(QUEUE+0x10) == self.qword(QUEUE+0x30):
                self.stop_on_empty = True
                u.emu_stop()
                return
        if address in (0x1794224, 0x1794280, 0x17b0adc, 0x165fe40,
                       0x36804c8, 0x35aa4b4):
            self.events.append('fixture: lock/condition/log boundary ' + hex(address))
            self.ret()
            return
        if address in (0x165d3e0, 0x165f820, 0x165d270):
            dst, src, count = (u.reg_read(X(i)) for i in range(3))
            assert count <= 0x1000 or (address == 0x165d270 and dst == 0x8894a78 and count == 0xbc50)
            self.ensure(dst, count)
            if address == 0x165d270:
                self.write(dst, bytes([src & 255]) * count)
                self.ret(dst)
            else:
                self.ensure(src, count)
                value = bytes(u.mem_read(src, count))
                if address == 0x165f820:
                    self.ret(int(bytes(u.mem_read(dst, count)) != value))
                else:
                    self.write(dst, value)
                    self.memcopies.append((dst, src, count))
                    self.ret(dst)
            return
        if address == 0x165fcc0:
            count = u.reg_read(X(0))
            assert 0 < count <= 32
            pointer = self.heap
            self.heap += (count + 15) & ~15
            self.write(pointer, bytes(count))
            self.allocations.add(pointer)
            self.ret(pointer)
            return
        if address == 0x165ef40:
            self.allocations.remove(u.reg_read(X(0)))
            self.ret()
            return
        if address == 0x165d810:
            keys, pointers, sizes = (u.reg_read(X(i)) for i in range(3))
            rows = []
            for i in range(3):
                key = self.word(keys + 4*i)
                if not key:
                    break
                assert i < 2
                pointer, length = self.qword(pointers + 8*i), self.word(sizes + 4*i)
                record = next(r for r in self.records if r[3] == key)
                assert (pointer, length) == (record[7], record[5])
                payload = self.storage[key]
                assert len(payload) == length
                self.write(pointer, payload)
                rows.append({'key': key, 'length': length, 'bytes': payload.hex()})
            assert len(rows) == 2
            self.backup_reads.append(rows)
            self.ret(len(rows) if self.read_count_override is None else self.read_count_override)
            return
        if address == 0x165eb40:
            subsystem, key, pointer = (u.reg_read(X(i)) for i in range(3))
            record = next(r for r in self.records if r[3] == key)
            assert subsystem == key >> 16
            self.backup_calls.append({'subsystem': subsystem, 'key': key,
                                      'bytes': bytes(u.mem_read(pointer, record[5])).hex()})
            self.storage[key] = bytes(u.mem_read(pointer, record[5]))
            self.ret(0)  # only a captured API boundary, no storage is written
            return
        if address == 0x3682634:
            self.events.append('fixture: Backup change notification boundary')
            self.ret()
            return
        super().code(u, address, size, data)

    def commit(self, values, cached):
        self.write(DIRTY, bytes(0x930))
        for i, (value, previous) in enumerate(zip(values, cached)):
            mid, _, _, key, _, length, _, buffer = self.records[i]
            self.put((0x7e705f8, 0x7e70628)[i], value)
            self.write(buffer, bytes([previous]) + b'\xa5\xa5\xa5')
            self.storage[key] = bytes([previous])
            bitbyte = DIRTY + mid // 8
            self.ensure(bitbyte, 1)
            self.write(bitbyte, bytes([self.u.mem_read(bitbyte, 1)[0] | (1 << (mid % 8))]))
        self.put(0x8838b40, 2)
        self.run(0x2f3a11c, allowed=ALLOWED)
        assert bytes(self.u.mem_read(DIRTY, 0x930)) == bytes(0x930)
        assert self.word(0x8838b40) == 1
        for i, r in enumerate(self.records):
            assert bytes(self.u.mem_read(r[7], 4)) == bytes([values[i]]) + b'\xa5\xa5\xa5'
        begin, end = self.qword(QUEUE+0x10), self.qword(QUEUE+0x30)
        messages = [bytes(self.u.mem_read(at, 16)) for at in range(begin, end, 16)]
        expected = [struct.pack('<IIB7x', 1, r[0], 0) for i, r in enumerate(self.records) if values[i] != cached[i]]
        assert messages == expected
        return [m.hex() for m in messages]

    def load_cache(self, count_override=None):
        self.read_count_override = count_override
        self.run(0x2e8cb70, allowed=ALLOWED + ((0x2e8cb70, 0x2e8cd7c), (0x35aa8bc, 0x35aa8c0)))
        assert not self.allocations
        success = count_override is None or count_override == 2
        assert bytes(self.u.mem_read(0x88d92c9, 1)) == bytes([success])
        if success:
            for r in self.records:
                assert bytes(self.u.mem_read(r[7], 4)) == self.storage[r[3]] + bytes(3)

    def consume(self):
        self.allowed = list(ALLOWED) + [(0x2850000, 0x28a0000)]
        self.worker = True
        self.u.reg_write(a.UC_ARM64_REG_SP, STACK + 0xff00)
        self.u.reg_write(a.UC_ARM64_REG_LR, STOP)
        self.ensure(0x2ff07ac, 4)
        self.u.emu_start(0x2ff07ac, STOP, count=20000)
        assert self.stop_on_empty and self.u.reg_read(a.UC_ARM64_REG_PC) == 0x2ff07ec
        # Infinite worker intentionally stops before its next wait; it has
        # not returned, so this is not an ABI-return or shutdown assertion.


def main():
    raw = (HERE / 'dev-menu-02/candidate/appFw.so').read_bytes()
    elf = ELFFile(io.BytesIO(raw))
    rela = elf.get_section_by_name('.rela.plt')
    symbols = elf.get_section(rela['sh_link'])
    plt = elf.get_section_by_name('.plt')['sh_addr']
    imports = {plt+32+16*i: symbols.get_symbol(r['r_info_sym']).name
               for i, r in enumerate(rela.iter_relocations())}
    assert imports[0x165eb40] == 'Backup_write'
    assert imports[0x165d810] == 'Backup_nread_multi'
    cases = []
    for pp in (12, 13, 14, 15):
        for cached in ((0, 2), (pp, 2), (0, 7), (pp, 7)):
            n = Commit(raw)
            messages = n.commit((pp, 7), cached)
            n.consume()
            expected = [{'subsystem': 0x2cf, 'key': r[3], 'bytes': bytes([v]).hex()}
                        for r, v, old in zip(n.records, (pp, 7), cached) if v != old]
            assert n.backup_calls == expected
            reader = Commit(raw)
            reader.storage = dict(n.storage)
            reader.load_cache()
            cases.append({'pp': pp, 'lut': 7, 'cached': cached, 'messages': messages,
                          'backup_write_calls': n.backup_calls, 'fresh_cache_read': reader.backup_reads})
    failed_reader = Commit(raw)
    failed_reader.storage = {0x02cf0053: b'\x0c', 0x02cf102d: b'\x07'}
    failed_reader.load_cache(count_override=1)
    report = {'status': 'NATIVE_COMMIT_WORKER_AND_CACHE_READ_API_BOUNDARIES_VERIFIED',
              'camera_io': False, 'candidate_flash_ready': False, 'ap_sha256': digest(raw),
              'sources': {n: digest((HERE / n).read_bytes()) for n in
                          ('verify_settings_commit.py', 'verify_menu.py', 'build.py')},
              'storage_record_file_offsets': ROWS, 'cases': cases,
              'actual_instructions': ['model_setting_value::commit 0x2f3a11c',
                                      'Model callback and native hash lookup',
                                      'Message builder 0x2e90554 and queue producer 0x2e902fc',
                                      'Worker 0x2ff07ac queue consume and message type 1 dispatch',
                                      'Conversion-map lookup with all 167 original entries',
                                      'Backup_write wrapper 0x35aa890',
                                      'Batch cache read 0x2e8cb70 through Backup_nread_multi wrapper',
                                      'Short batch result clears original cache-valid flag'],
              'fixtures': ['Hash container layout populated from exact original rows',
                           'Dirty bits and runtime flags; no upstream notification execution',
                           'Mutex/condition/log/libc and Backup service boundary'],
              'not_verified': ['Actual nonvolatile service write, failure behavior or sync',
                               'Complete startup and cache-to-model population',
                               'Still/movie independent settings, MR or full menu events',
                               'LUT file upload, resource lifetime or camera JPEG']}
    (HERE / 'dev-menu-02/settings-commit-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'camera_io': False, 'cases': len(cases)}, indent=2))


if __name__ == '__main__':
    main()
