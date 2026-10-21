"""Host journal -> generated const C plan -> native core -> receipt -> readback."""
import ctypes as c
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from install_transaction import Package, Transaction, Rejected, PROGRAMS, canonical, digest
from native_pair_backend import NativePairBackend, FixedWindows
import test_native_pair_core as native

IDENTITY = {'model': 'bridge-fixture', 'serial': 'offline-only'}
HERE = Path(__file__).resolve().parent


def make_package(root, before, after, windows):
    manifest = {'inputs': {n: digest(before[i]) for i, n in enumerate(PROGRAMS)},
                'outputs': {n: {'sha256': digest(after[i]), 'size': len(after[i])}
                            for i, n in enumerate(PROGRAMS)}, 'patches': []}
    for file, at, size in windows:
        manifest['patches'].append({'file': PROGRAMS[file], 'offset': at, 'length': size,
                                    'before': before[file][at:at+size].hex(),
                                    'after': after[file][at:at+size].hex()})
    raw = canonical(manifest)
    for role, pair in [('baseline', before), ('candidate', after)]:
        (root / role).mkdir(parents=True)
        for n, data in zip(PROGRAMS, pair): (root / role / n).write_bytes(data)
    package = {'format': 1, 'identity_sha256': digest(canonical(IDENTITY)),
               'hardware_adapter_available': False, 'firmware_manifest_sha256': digest(raw),
               'programs': {n: {role: {'sha256': digest(pair[i]), 'size': len(pair[i])}
                                for role, pair in [('baseline', before), ('candidate', after)]}
                            for i, n in enumerate(PROGRAMS)},
               'readiness': {'status': 'READY_FOR_CONTROLLED_FLASH',
                             'candidate_sha256': {n: digest(after[i]) for i, n in enumerate(PROGRAMS)}}}
    (root / 'package.json').write_bytes(canonical(package))
    return Package(root), raw


class LocalSession:
    kind = 'offline-fixture'

    def __init__(self, root, before, journal):
        root.mkdir()
        self.files = native.Files(root, before)
        self.journal = journal
        self.calls, self.bundles = [], []
        self.target = dict(IDENTITY)
        self.fault = None

    def identity(self):
        self.calls.append('identity')
        return self.target

    def read_program(self, name):
        self.calls.append('read_' + name)
        return self.files.paths[PROGRAMS.index(name)].read_bytes()

    def run_native(self, bundle):
        self.calls.append('native')
        self.bundles.append(bundle)
        metadata = json.loads(bundle.metadata)
        assert metadata['header_sha256'] == digest(bundle.header)
        # Independent check that the entire native scope was journaled before
        # this invocation, including the exact source and target file hashes.
        journal = json.loads((self.journal / 'journal.json').read_text())
        event = journal['events'][-1]
        assert journal['phase'].endswith('_PAIR_WRITE_INTENT')
        assert event['operation_id'] == bundle.operation_id
        assert event['expected_current_sha256'] == metadata['before_sha256']
        assert event['target_sha256'] == metadata['after_sha256']
        with tempfile.TemporaryDirectory(prefix='lut-operation-plan-') as directory:
            directory = Path(directory)
            (directory / 'operation.h').write_bytes(bundle.header)
            (directory / 'module.c').write_text('#include "operation.h"\n#include "pair_core.c"\n'
                                                'const struct lp_plan *test_plan(void){return &operation_plan;}\n')
            libpath = directory / 'module.dylib'
            subprocess.run(['clang', '-std=c11', '-O2', '-fno-builtin', '-Wall', '-Wextra', '-Werror',
                            '-dynamiclib', '-I', str(HERE / 'native'), str(directory / 'module.c'),
                            '-o', str(libpath)], check=True, capture_output=True)
            lib = c.CDLL(str(libpath))
            lib.lp_run.argtypes = [c.POINTER(native.Plan), c.POINTER(native.IO),
                                  c.POINTER(native.Workspace), c.POINTER(native.Report)]
            lib.lp_run.restype = None
            lib.test_plan.restype = c.POINTER(native.Plan)
            plan = lib.test_plan().contents
            assert bytes(plan.operation_id).hex() == bundle.operation_id
            self.files.failed = False
            report = self.files.run(lib, plan)
        if self.fault == 'response_lost':
            raise TimeoutError('native completed, report transport lost')
        if self.fault == 'stale_operation_report':
            report.operation_id[0] ^= 1
        if self.fault == 'changed_after_report':
            self.files.paths[1].write_bytes(b'changed-before-host-readback')
        return bytes(report)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='lut-bridge-')
        self.root = Path(self.temp.name)
        self.before = [b'A' * 500, b'C' * 600]
        self.after = [b'A' * 20 + b'new-ap-1' + b'A' * 472,
                      b'C' * 30 + b'new-cp-2' + b'C' * 562]
        self.windows = [(0, 20, 8), (1, 30, 8)]
        self.package, self.manifest = make_package(self.root / 'package', self.before, self.after, self.windows)
        self.journal = self.root / 'transaction'
        self.session = LocalSession(self.root / 'files', self.before, self.journal)
        self.backend = NativePairBackend(self.package, self.manifest, self.session)

    def tearDown(self):
        self.temp.cleanup()

    def open(self):
        return Transaction(self.package, self.journal)

    def test_complete_native_install_and_restore_through_host_transaction(self):
        with self.open() as t:
            t.install(self.backend)
            self.assertEqual(t.state['phase'], 'INSTALL_READBACK_VERIFIED')
            self.assertEqual([p.read_bytes() for p in self.session.files.paths], self.after)
            t.restore(self.backend, t.inspect(self.backend))
            self.assertEqual(t.state['phase'], 'RESTORE_READBACK_VERIFIED')
            self.assertEqual([p.read_bytes() for p in self.session.files.paths], self.before)
            self.assertEqual(self.session.calls.count('native'), 2)
            self.assertNotEqual(self.session.bundles[0].operation_id, self.session.bundles[1].operation_id)

    def test_native_partial_write_rollback_stops_host_install(self):
        self.session.files.fault = 'partial_1'
        with self.open() as t:
            with self.assertRaises(Rejected): t.install(self.backend)
            self.assertEqual(t.state['phase'], 'NEEDS_REVIEW')
            receipts = [e for e in t.state['events'] if e['phase'] == 'INSTALL_PAIR_RECEIPT_VERIFIED']
            self.assertEqual(receipts[0]['outcome'], 'rolled_back')
            self.assertEqual([p.read_bytes() for p in self.session.files.paths], self.before)
            with self.assertRaises(Rejected): t.install(self.backend)
            self.assertEqual(self.session.calls.count('native'), 1)

    def test_missing_or_stale_report_never_reinvokes_native(self):
        for fault in ('response_lost', 'stale_operation_report'):
            with self.subTest(fault=fault):
                self.session.fault = fault
                self.journal = self.root / fault
                self.session.journal = self.journal
                for p, data in zip(self.session.files.paths, self.before): p.write_bytes(data)
                self.session.calls = []
                with self.open() as t:
                    with self.assertRaises((Rejected, TimeoutError)): t.install(self.backend)
                    self.assertEqual(t.state['phase'], 'NEEDS_REVIEW')
                with self.open() as t:
                    with self.assertRaises(Rejected): t.install(self.backend)
                    self.assertEqual(self.session.calls.count('native'), 1)
                    self.session.fault = None
                    t.restore(self.backend, t.inspect(self.backend))
                    self.assertEqual(t.state['phase'], 'RESTORE_READBACK_VERIFIED')

    def test_host_readback_does_not_trust_successful_c_report(self):
        self.session.fault = 'changed_after_report'
        with self.open() as t:
            with self.assertRaises(Rejected): t.install(self.backend)
            self.assertEqual(t.state['phase'], 'NEEDS_REVIEW')
            self.assertEqual(self.session.calls.count('native'), 1)

    def test_partial_window_recovery_uses_exact_fresh_preimage(self):
        self.session.fault = 'response_lost'
        with self.open() as t:
            with self.assertRaises(TimeoutError): t.install(self.backend)
            raw = bytearray(self.session.files.paths[0].read_bytes())
            raw[20:23] = b'???'
            self.session.files.paths[0].write_bytes(raw)
            inspection = t.inspect(self.backend)
            self.session.fault = None
            t.restore(self.backend, inspection)
            self.assertEqual([p.read_bytes() for p in self.session.files.paths], self.before)
            self.assertEqual(t.state['phase'], 'RESTORE_READBACK_VERIFIED')

    def test_outside_window_corruption_is_not_overwritten(self):
        with self.open() as t:
            t.install(self.backend)
            raw = bytearray(self.session.files.paths[0].read_bytes())
            raw[0] = ord('?')
            self.session.files.paths[0].write_bytes(raw)
            with self.assertRaisesRegex(Rejected, 'outside approved native windows'):
                t.restore(self.backend, t.inspect(self.backend))
            self.assertEqual(self.session.calls.count('native'), 1)
            self.assertEqual(self.session.files.paths[0].read_bytes(), bytes(raw))

    def test_manifest_binding_rejected_without_session_calls(self):
        with self.assertRaises(Rejected):
            NativePairBackend(self.package, self.manifest + b' ', self.session)
        self.assertEqual(self.session.calls, [])

    def test_hardware_session_is_gated_before_access(self):
        self.session.kind = 'hardware'
        backend = NativePairBackend(self.package, self.manifest, self.session)
        with self.open() as t, self.assertRaises(Rejected): t.install(backend)
        self.assertEqual(self.session.calls, [])

    def test_generated_header_is_deterministic_and_candidate_bound(self):
        fixed = FixedWindows(self.package, self.manifest)
        current, target = dict(zip(PROGRAMS, self.before)), dict(zip(PROGRAMS, self.after))
        hashes = {n: digest(raw) for n, raw in current.items()}
        a = fixed.prepare(current, target, hashes, '1' * 64)
        b = fixed.prepare(current, target, hashes, '1' * 64)
        self.assertEqual(a, b)
        self.assertEqual(a.sha256, b.sha256)
        target[PROGRAMS[0]] = b'X' * len(target[PROGRAMS[0]])
        with self.assertRaises(Rejected): fixed.prepare(current, target, hashes, '1' * 64)


if __name__ == '__main__':
    unittest.main(verbosity=2)
