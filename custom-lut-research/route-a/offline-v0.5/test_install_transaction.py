"""Fault injection against the offline transaction core; no camera imports."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from install_transaction import Package, Transaction, Rejected, PROGRAMS, canonical, digest

IDENTITY = {'model': 'test-device', 'version': 'test-version', 'serial': 'test-only'}
BASE = {n: ('old-' + n).encode() * 17 for n in PROGRAMS}
NEW = {n: ('new-' + n).encode() * 17 for n in PROGRAMS}


class FakeDevice:
    kind = 'offline-fixture'

    def __init__(self, root):
        self.root = root
        root.mkdir()
        for name, raw in BASE.items():
            (root / name).write_bytes(raw)
        self.target = dict(IDENTITY)
        self.calls = []
        self.fault = None
        self.transaction = None

    def identity(self):
        self.calls.append(('identity',))
        return self.target

    def read_program(self, name):
        self.calls.append(('read', name))
        return (self.root / name).read_bytes()

    def write_program(self, name, raw):
        self.calls.append(('write', name))
        # Independent oracle: every external mutation must already have a
        # durable intent for this exact file and payload, not just RAM state.
        journal = json.loads((self.transaction / 'journal.json').read_text())
        assert journal['phase'].endswith('_WRITE_INTENT')
        assert journal['events'][-1]['program'] == name
        assert journal['events'][-1]['expected_sha256'] == digest(raw)
        mode = self.fault.get(name) if self.fault else None
        if mode == 'before':
            raise OSError('injected before write')
        if mode == 'partial':
            (self.root / name).write_bytes(raw[:3])
            raise OSError('injected partial write')
        if mode == 'corrupt':
            (self.root / name).write_bytes(raw[:-1] + b'?')
            return
        (self.root / name).write_bytes(raw)
        if mode == 'after':
            raise OSError('injected after complete write')
        if mode == 'interrupt':
            raise KeyboardInterrupt()


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.package_root = self.root / 'package'
        self.package_root.mkdir()
        for role, files in [('baseline', BASE), ('candidate', NEW)]:
            (self.package_root / role).mkdir()
            for name, raw in files.items():
                (self.package_root / role / name).write_bytes(raw)
        self.manifest = {'format': 1, 'identity_sha256': digest(canonical(IDENTITY)),
                         'programs': {n: {role: {'sha256': digest(files[n]), 'size': len(files[n])}
                                         for role, files in [('baseline', BASE), ('candidate', NEW)]}
                                      for n in PROGRAMS},
                         'readiness': {'status': 'READY_FOR_CONTROLLED_FLASH',
                                       'candidate_sha256': {n: digest(NEW[n]) for n in PROGRAMS}}}
        self.save_manifest()
        self.device = FakeDevice(self.root / 'device')
        self.journal = self.root / 'transaction'
        self.device.transaction = self.journal

    def tearDown(self):
        self.temp.cleanup()

    def save_manifest(self):
        (self.package_root / 'package.json').write_bytes(canonical(self.manifest))

    def open(self):
        return Transaction(Package(self.package_root), self.journal)

    def writes(self):
        return [c for c in self.device.calls if c[0] == 'write']

    def test_install_readback_then_explicit_restore(self):
        with self.open() as t:
            t.install(self.device)
            self.assertEqual(t.state['phase'], 'INSTALL_READBACK_VERIFIED')
            self.assertFalse(t.state['events'][-1]['boot_verified'])
            self.assertEqual(len(self.writes()), 2)
            t.restore(self.device, t.inspect(self.device))
            self.assertEqual(t.state['phase'], 'RESTORE_READBACK_VERIFIED')
        for n in PROGRAMS:
            self.assertEqual(self.device.read_program(n), BASE[n])

    def test_unreleased_does_not_even_identify_device(self):
        self.manifest['readiness']['status'] = 'NOT_READY_TO_FLASH'
        self.save_manifest()
        with self.open() as t, self.assertRaises(Rejected):
            t.install(self.device)
        self.assertEqual(self.device.calls, [])

    def test_wrong_identity_or_either_baseline_stops_before_all_writes(self):
        for variation in ('identity', *PROGRAMS):
            with self.subTest(variation=variation):
                old_target = dict(self.device.target)
                if variation == 'identity':
                    self.device.target['serial'] = 'wrong'
                else:
                    (self.device.root / variation).write_bytes(b'changed')
                self.journal = self.root / ('transaction-' + variation)
                self.device.transaction = self.journal
                with self.open() as t:
                    with self.assertRaises(Rejected):
                        t.install(self.device)
                    self.assertFalse(self.writes())
                    self.device.target = old_target
                    for n in PROGRAMS:
                        (self.device.root / n).write_bytes(BASE[n])
                    with self.assertRaises(Rejected):
                        t.restore(self.device, t.inspect(self.device))

    def test_fault_matrix_reopen_no_retry_inspect_restore(self):
        for name in PROGRAMS:
            for fault in ('before', 'partial', 'corrupt', 'after', 'interrupt'):
                with self.subTest(name=name, fault=fault):
                    self.journal = self.root / ('transaction-' + name + '-' + fault)
                    self.device.transaction = self.journal
                    for n in PROGRAMS:
                        (self.device.root / n).write_bytes(BASE[n])
                    self.device.calls = []
                    self.device.fault = {name: fault}
                    with self.open() as t:
                        with self.assertRaises((OSError, Rejected, KeyboardInterrupt)):
                            t.install(self.device)
                        self.assertEqual(t.state['phase'], 'NEEDS_REVIEW')
                    attempted = len(self.writes())
                    with self.open() as t:
                        with self.assertRaises(Rejected):
                            t.install(self.device)
                        self.assertEqual(len(self.writes()), attempted)
                        inspection = t.inspect(self.device)
                        self.device.fault = None
                        t.restore(self.device, inspection)
                        self.assertEqual(t.state['phase'], 'RESTORE_READBACK_VERIFIED')
                    for n in PROGRAMS:
                        self.assertEqual(self.device.read_program(n), BASE[n])

    def test_stale_recovery_inspection_writes_nothing(self):
        with self.open() as t:
            t.install(self.device)
            inspection = t.inspect(self.device)
            (self.device.root / PROGRAMS[1]).write_bytes(b'changed since review')
            count = len(self.writes())
            with self.assertRaises(Rejected):
                t.restore(self.device, inspection)
            self.assertEqual(len(self.writes()), count)

    def test_corrupted_package_is_rejected(self):
        for role in ('baseline', 'candidate'):
            for name in PROGRAMS:
                with self.subTest(role=role, name=name):
                    p = self.package_root / role / name
                    raw = p.read_bytes()
                    p.write_bytes(raw + b'bad')
                    with self.assertRaises(Rejected):
                        Package(self.package_root)
                    p.write_bytes(raw)

    def test_lock_prevents_two_writers(self):
        with self.open():
            with self.assertRaises(Rejected):
                self.open()

    def test_mismatched_readiness_pair_rejected_before_io(self):
        self.manifest['readiness']['candidate_sha256'][PROGRAMS[0]] = '0' * 64
        self.save_manifest()
        with self.open() as t, self.assertRaises(Rejected):
            t.install(self.device)
        self.assertEqual(self.device.calls, [])

    def test_foreign_journal_rejected(self):
        with self.open() as t:
            t.install(self.device)
        self.manifest['identity_sha256'] = '0' * 64
        self.save_manifest()
        with self.assertRaises(Rejected):
            self.open()

    def test_hardware_adapter_absent_blocks_before_identity(self):
        self.device.kind = 'hardware'
        with self.open() as t, self.assertRaises(Rejected):
            t.install(self.device)
        self.assertEqual(self.device.calls, [])

    def test_backend_kind_cannot_change_between_install_and_restore(self):
        with self.open() as t:
            t.install(self.device)
            self.device.calls = []
            self.device.kind = 'hardware'
            with self.assertRaises(Rejected):
                t.inspect(self.device)
        self.assertEqual(self.device.calls, [])

    def test_process_death_preserves_intent_and_releases_host_lock(self):
        for name in PROGRAMS:
            with self.subTest(program=name):
                self.journal = self.root / ('crash-' + name)
                self.device.transaction = self.journal
                for n in PROGRAMS:
                    (self.device.root / n).write_bytes(BASE[n])
                script = '''
import os, sys
from pathlib import Path
from test_install_transaction import FakeDevice, IDENTITY
from install_transaction import Package, Transaction
class CrashingDevice(FakeDevice):
    def write_program(self, name, raw):
        super().write_program(name, raw)
        if name == sys.argv[4]:
            os._exit(77)
d = object.__new__(CrashingDevice)
d.root, d.transaction = Path(sys.argv[2]), Path(sys.argv[3])
d.target, d.calls, d.fault = IDENTITY, [], None
with Transaction(Package(sys.argv[1]), d.transaction) as t:
    t.install(d)
'''
                result = subprocess.run([sys.executable, '-c', script, str(self.package_root),
                                         str(self.device.root), str(self.journal), name],
                                        cwd=Path(__file__).resolve().parent, capture_output=True)
                self.assertEqual(result.returncode, 77, result.stderr)
                with self.open() as t:
                    self.assertEqual(t.state['phase'], 'INSTALL_WRITE_INTENT')
                    self.assertEqual(t.state['events'][-1]['program'], name)
                    with self.assertRaises(Rejected):
                        t.install(self.device)
                    t.restore(self.device, t.inspect(self.device))
                for n in PROGRAMS:
                    self.assertEqual(self.device.read_program(n), BASE[n])


if __name__ == '__main__':
    unittest.main(verbosity=2)
