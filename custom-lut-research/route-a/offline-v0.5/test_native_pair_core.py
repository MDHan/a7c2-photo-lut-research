"""Run the actual C engine against temporary files with syscall fault injection."""
import ctypes as c
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from native_pair_report import decode_receipt, LAYOUT
from install_transaction import Rejected, PROGRAMS

HERE = Path(__file__).resolve().parent
U8, U32, U64, I64 = c.c_ubyte, c.c_uint32, c.c_uint64, c.c_int64
Ptr = c.POINTER(U8)
HashPair = (U8 * 32) * 2


class Stat(c.Structure):
    _fields_ = [('device', U64), ('inode', U64), ('size', U64),
                ('mode', U32), ('uid', U32), ('gid', U32), ('links', U32)]


class Window(c.Structure):
    _fields_ = [('offset', U64), ('file', U32), ('length', U32), ('before', Ptr), ('after', Ptr)]


class Plan(c.Structure):
    _fields_ = [('size', U64 * 2), ('before_hash', HashPair), ('after_hash', HashPair),
                ('operation_id', U8 * 32), ('windows', c.POINTER(Window)), ('count', U32)]


class Report(c.Structure):
    _fields_ = [(n, U32) for n in ('version', 'outcome', 'phase', 'source_verified', 'writes_started', 'rollback_verified')]
    _fields_ += [(n, I64) for n in ('status', 'rollback_status', 'cleanup_status')]
    _fields_ += [('operation_id', U8 * 32), ('before_hash', HashPair), ('after_hash', HashPair)]


class Workspace(c.Structure):
    _fields_ = [('buffer', U8 * 4096), ('original', Stat * 2), ('fd', I64 * 2)]


Fn0 = c.CFUNCTYPE(I64, c.c_void_p)
FnMode = c.CFUNCTYPE(I64, c.c_void_p, U32)
FnOpen = c.CFUNCTYPE(I64, c.c_void_p, U32, U32)
FnFd = c.CFUNCTYPE(I64, c.c_void_p, I64)
FnStat = c.CFUNCTYPE(I64, c.c_void_p, I64, c.POINTER(Stat))
FnData = c.CFUNCTYPE(I64, c.c_void_p, I64, c.c_void_p, U32, U64)


class IO(c.Structure):
    _fields_ = [('context', c.c_void_p), ('begin', Fn0), ('end', Fn0),
                ('writable', FnMode), ('open', FnOpen), ('close', FnFd),
                ('stat', FnStat), ('read', FnData), ('write', FnData), ('sync', FnFd)]


def make_plan(before, after, windows):
    plan = Plan()
    arrays = []
    rows = (Window * len(windows))()
    for i in range(2):
        assert len(before[i]) == len(after[i])
        plan.size[i] = len(before[i])
        plan.before_hash[i][:] = hashlib.sha256(before[i]).digest()
        plan.after_hash[i][:] = hashlib.sha256(after[i]).digest()
    plan.operation_id[:] = hashlib.sha256(b'offline-native-test-operation').digest()
    for i, (file, offset, length) in enumerate(windows):
        a = (U8 * length).from_buffer_copy(before[file][offset:offset + length])
        b = (U8 * length).from_buffer_copy(after[file][offset:offset + length])
        arrays.extend((a, b))
        rows[i] = Window(offset, file, length, a, b)
    plan.windows, plan.count = rows, len(rows)
    plan.keepalive = arrays, rows
    return plan


class Files:
    def __init__(self, root, before, fault=None):
        self.root, self.fault = root, fault
        self.paths = [root / 'ap.bin', root / 'cp.bin']
        for path, raw in zip(self.paths, before):
            path.write_bytes(raw)
        self.fds, self.events, self.errors = {}, [], []
        self.lock = None
        self.rw = False
        self.failed = False
        self.did_write = False
        self.read_interrupts = 0
        self.callbacks = []
        def wrap(kind, method):
            def invoke(ctx, *args):
                try:
                    return method(*args)
                except BaseException as error:
                    self.errors.append(repr(error))
                    return -99
            result = kind(invoke)
            self.callbacks.append(result)
            return result
        self.io = IO(None, wrap(Fn0, self.begin), wrap(Fn0, self.end),
                     wrap(FnMode, self.writable), wrap(FnOpen, self.open),
                     wrap(FnFd, self.close), wrap(FnStat, self.stat),
                     wrap(FnData, self.read), wrap(FnData, self.write), wrap(FnFd, self.sync))

    def once(self, name):
        if self.fault == name and not self.failed:
            self.failed = True
            return True
        return False

    def begin(self):
        self.events.append('begin')
        self.lock = (self.root / 'native.lock').open('a+b')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return 0

    def end(self):
        self.events.append('end')
        assert self.lock is not None
        fcntl.flock(self.lock, fcntl.LOCK_UN)
        self.lock.close()
        self.lock = None
        return -5 if self.fault == 'session_end' else 0

    def writable(self, enabled):
        self.events.append('rw' if enabled else 'ro')
        self.rw = bool(enabled)
        if enabled and self.once('inode_changed'):
            data = self.paths[0].read_bytes()
            replacement = self.root / 'replacement'
            replacement.write_bytes(data)
            os.replace(replacement, self.paths[0])
        if enabled and self.once('source_changed'):
            self.paths[1].write_bytes(b'changed'.ljust(self.paths[1].stat().st_size, b'?'))
        if enabled and self.once('rw_failed_after_change'):
            return -5
        if not enabled and self.did_write and self.fault == 'readonly_cleanup':
            return -5
        return 0

    def open(self, file, writable):
        assert file in (0, 1) and self.lock is not None
        assert not writable or self.rw
        if writable and file == 1 and self.once('cp_reopen'):
            return -13
        fd = os.open(self.paths[file], (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW)
        self.fds[fd] = file, writable
        self.events.append(('open', file, writable))
        return fd

    def close(self, fd):
        file, writable = self.fds.pop(fd)
        os.close(fd)
        self.events.append(('close', file, writable))
        return -5 if writable and self.once('close_cleanup') else 0

    def stat(self, fd, out):
        st = os.fstat(fd)
        out[0] = Stat(st.st_dev, st.st_ino, st.st_size, st.st_mode, st.st_uid, st.st_gid, st.st_nlink)
        return 0

    def read(self, fd, pointer, count, offset):
        if self.fault == 'read_eintr' and self.read_interrupts < 2:
            self.read_interrupts += 1
            return -4
        if self.fault == 'read_eintr_forever':
            return -4
        if self.did_write and self.once('target_read_failure'):
            return -5
        if self.fault == 'short_io':
            count = min(count, 13)
        raw = os.pread(fd, count, offset)
        c.memmove(pointer, raw, len(raw))
        return len(raw)

    def write(self, fd, pointer, count, offset):
        file, writable = self.fds[fd]
        assert self.rw and writable and self.lock is not None
        self.events.append(('write', file, offset, count))
        self.did_write = True
        if self.fault == 'write_persistent':
            return -5
        if self.once('write_zero'):
            return 0
        if self.once('write_eintr'):
            return -4
        if self.once('partial_' + str(file)):
            os.pwrite(fd, c.string_at(pointer, min(3, count)), offset)
            return -5
        if self.fault == 'short_io':
            count = min(count, 3)
        return os.pwrite(fd, c.string_at(pointer, count), offset)

    def sync(self, fd):
        self.events.append(('sync', self.fds[fd][0]))
        os.fsync(fd)
        if self.fault == 'sync_persistent' or self.once('sync_once'):
            return -5
        if self.once('outside_window_corruption'):
            os.pwrite(fd, b'!', 0)
        return 0

    def run(self, lib, plan):
        report, workspace = Report(), Workspace()
        lib.lp_run(c.byref(plan), c.byref(self.io), c.byref(workspace), c.byref(report))
        assert not self.errors, self.errors
        assert not self.fds and self.lock is None
        return report


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_dir = tempfile.TemporaryDirectory(prefix='lut-native-core-build-')
        lib = Path(cls.build_dir.name) / 'pair_core.dylib'
        cls.command = ['clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-builtin',
                       '-dynamiclib', str(HERE / 'native/pair_core.c'), '-o', str(lib)]
        subprocess.run(cls.command, check=True, capture_output=True)
        cls.lib = c.CDLL(str(lib))
        cls.lib.lp_run.argtypes = [c.POINTER(Plan), c.POINTER(IO), c.POINTER(Workspace), c.POINTER(Report)]
        cls.lib.lp_run.restype = None

    @classmethod
    def tearDownClass(cls):
        cls.build_dir.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='lut-native-files-')
        self.root = Path(self.temp.name)
        self.before = [bytes((i * 7 + f) % 251 for i in range(8200 + f)) for f in range(2)]
        self.windows = [(0, 101, 7), (0, 4090, 6), (1, 77, 11)]
        self.after = [bytearray(raw) for raw in self.before]
        for f, at, size in self.windows:
            self.after[f][at:at + size] = b'X' * size
        self.after = list(map(bytes, self.after))
        self.plan = make_plan(self.before, self.after, self.windows)

    def tearDown(self):
        self.temp.cleanup()

    def test_native_success_short_io_and_interrupted_io(self):
        for mode in (None, 'short_io', 'read_eintr', 'write_eintr'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=self.root) as directory:
                files = Files(Path(directory), self.before, mode)
                inode = [p.stat().st_ino for p in files.paths]
                r = files.run(self.lib, self.plan)
                self.assertEqual((r.status, r.outcome, r.phase), (0, 1, 8))
                self.assertEqual([p.read_bytes() for p in files.paths], self.after)
                self.assertEqual([p.stat().st_ino for p in files.paths], inode)
                self.assertEqual(bytes(r.operation_id), bytes(self.plan.operation_id))
                self.assertEqual([bytes(x) for x in r.after_hash], [hashlib.sha256(x).digest() for x in self.after])
                self.assertFalse(files.rw)

    def test_native_write_and_target_failures_verified_rollback(self):
        for mode in ('write_zero', 'partial_0', 'partial_1', 'sync_once', 'target_read_failure'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=self.root) as directory:
                files = Files(Path(directory), self.before, mode)
                r = files.run(self.lib, self.plan)
                self.assertNotEqual(r.status, 0)
                self.assertEqual((r.outcome, r.rollback_verified, r.rollback_status), (2, 1, 0))
                self.assertEqual([p.read_bytes() for p in files.paths], self.before)
                self.assertFalse(files.rw)

    def test_native_failed_rollback_never_claims_recovery(self):
        for mode in ('write_persistent', 'sync_persistent', 'outside_window_corruption'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=self.root) as directory:
                files = Files(Path(directory), self.before, mode)
                r = files.run(self.lib, self.plan)
                self.assertEqual((r.outcome, r.rollback_verified), (0, 0))
                self.assertNotEqual(r.rollback_status, 0)

    def test_native_reopen_races_and_bounded_read_retries(self):
        for mode in ('inode_changed', 'source_changed', 'rw_failed_after_change', 'cp_reopen', 'read_eintr_forever'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=self.root) as directory:
                files = Files(Path(directory), self.before, mode)
                r = files.run(self.lib, self.plan)
                self.assertEqual((r.outcome, r.writes_started), (3, 0))
                self.assertFalse(files.did_write)
                self.assertFalse(files.rw)

    def test_native_cleanup_failure_overrides_success_claim(self):
        for mode in ('close_cleanup', 'readonly_cleanup', 'session_end'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=self.root) as directory:
                files = Files(Path(directory), self.before, mode)
                r = files.run(self.lib, self.plan)
                self.assertEqual((r.status, r.outcome), (0, 0))
                self.assertNotEqual(r.cleanup_status, 0)

    def test_native_bad_window_and_preimage_rejected(self):
        for mode in ('overlap', 'bounds', 'bad_preimage'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=self.root) as directory:
                plan = make_plan(self.before, self.after, self.windows)
                if mode == 'overlap': plan.windows[1].offset = 102
                elif mode == 'bounds': plan.windows[1].offset = plan.size[0]
                else: plan.windows[0].before[0] ^= 1
                files = Files(Path(directory), self.before)
                r = files.run(self.lib, plan)
                self.assertEqual((r.outcome, r.writes_started), (3, 0))
                self.assertEqual([p.read_bytes() for p in files.paths], self.before)
                if mode != 'bad_preimage': self.assertEqual(files.events, [])

    def test_native_report_protocol_requires_operation_hashes_and_cleanup(self):
        self.assertEqual(c.sizeof(Report), LAYOUT.size)
        before = {n: hashlib.sha256(self.before[i]).hexdigest() for i, n in enumerate(PROGRAMS)}
        after = {n: hashlib.sha256(self.after[i]).hexdigest() for i, n in enumerate(PROGRAMS)}
        op = bytes(self.plan.operation_id).hex()
        for mode, outcome in ((None, 'written'), ('partial_1', 'rolled_back')):
            with tempfile.TemporaryDirectory(dir=self.root) as directory:
                r = Files(Path(directory), self.before, mode).run(self.lib, self.plan)
                raw = bytes(r)
                receipt = decode_receipt(raw, op, before, after)
                self.assertEqual(receipt['outcome'], outcome)
                for field, value in [('cleanup_status', -5), ('source_verified', 0),
                                     ('writes_started', 0), ('outcome', 0), ('version', 2)]:
                    changed = Report.from_buffer_copy(raw)
                    setattr(changed, field, value)
                    with self.assertRaises(Rejected): decode_receipt(bytes(changed), op, before, after)
                with self.assertRaises(Rejected): decode_receipt(raw, '0' * 64, before, after)
                with self.assertRaises(Rejected): decode_receipt(raw[:-1], op, before, after)
                with self.assertRaises(Rejected): decode_receipt(raw, op, after, before)

    def test_actual_candidate_native_fixed_window_install_and_restore(self):
        folder = HERE / 'dev-menu-02'
        manifest = json.loads((folder / 'manifest.json').read_text())
        names = ('appFw.so', 'cpapp-b.bin')
        base = HERE.parents[2] / 'install-20261018-085012/candidate'
        before = [(base / n).read_bytes() for n in names]
        after = [(folder / 'candidate' / n).read_bytes() for n in names]
        for i, n in enumerate(names):
            self.assertEqual(hashlib.sha256(before[i]).hexdigest(), manifest['inputs'][n])
            self.assertEqual(hashlib.sha256(after[i]).hexdigest(), manifest['outputs'][n]['sha256'])
        windows = sorted((names.index(x['file']), x['offset'], x['length']) for x in manifest['patches'])
        files = Files(self.root, before)
        inode = [p.stat().st_ino for p in files.paths]
        r = files.run(self.lib, make_plan(before, after, windows))
        self.assertEqual((r.status, r.outcome), (0, 1))
        self.assertEqual([p.read_bytes() for p in files.paths], after)
        r = files.run(self.lib, make_plan(after, before, windows))
        self.assertEqual((r.status, r.outcome), (0, 1))
        self.assertEqual([p.read_bytes() for p in files.paths], before)
        self.assertEqual([p.stat().st_ino for p in files.paths], inode)


if __name__ == '__main__':
    unittest.main(verbosity=2)
