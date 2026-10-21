"""Pair-native adapter contract tests on temporary files; no camera code."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from install_transaction import Package, Transaction, Rejected, PROGRAMS, canonical, digest
import test_install_transaction as fixtures
from test_install_transaction import FakeDevice, BASE, NEW, IDENTITY


class PairDevice(FakeDevice):
    write_scope = 'pair'

    def write_program(self, *args):
        raise AssertionError('A pair backend must never be called once per file')

    def write_pair(self, programs, *, expected_current_sha256, operation_id):
        self.calls.append(('pair', operation_id))
        state = json.loads((self.transaction / 'journal.json').read_text())
        event = state['events'][-1]
        assert state['phase'].endswith('_PAIR_WRITE_INTENT')
        assert event['write_scope'] == 'pair' and event['operation_id'] == operation_id
        assert set(programs) == set(PROGRAMS)
        assert event['target_sha256'] == {n: digest(programs[n]) for n in PROGRAMS}
        assert event['expected_current_sha256'] == expected_current_sha256
        intent = {k: event[k] for k in ('package_sha256', 'action', 'identity_sha256',
                                        'sequence', 'expected_current_sha256', 'target_sha256')}
        assert digest(canonical(intent)) == operation_id
        if self.fault == 'source_changed_at_native_entry':
            (self.root / PROGRAMS[1]).write_bytes(b'concurrent-change')
        before = {n: (self.root / n).read_bytes() for n in PROGRAMS}
        if {n: digest(raw) for n, raw in before.items()} != expected_current_sha256:
            raise Rejected('Native pair compare rejected changed source')
        if self.fault == 'before':
            raise OSError('before native mutation')
        if self.fault == 'rejected_before_write':
            outcome = 'rejected_before_write'
        else:
            for index, name in enumerate(PROGRAMS):
                raw = programs[name]
                if self.fault == 'partial_' + str(index):
                    (self.root / name).write_bytes(raw[:3])
                    raise OSError('partial native write')
                (self.root / name).write_bytes(raw)
                if self.fault == 'after_' + str(index):
                    raise OSError('native write happened, response lost')
                if self.fault == 'death_' + str(index):
                    os._exit(77)
                if self.fault == 'interrupt_' + str(index):
                    raise KeyboardInterrupt()
            outcome = 'written'
            if self.fault == 'rolled_back':
                for n, raw in before.items():
                    (self.root / n).write_bytes(raw)
                outcome = 'rolled_back'
        after = {n: digest((self.root / n).read_bytes()) for n in PROGRAMS}
        receipt = {'format': 1, 'operation_id': operation_id, 'outcome': outcome,
                   'before_sha256': dict(expected_current_sha256), 'after_sha256': after}
        if self.fault == 'corrupt_after_receipt':
            (self.root / PROGRAMS[1]).write_bytes(b'corrupt')
        elif self.fault == 'missing_receipt':
            return None
        elif self.fault == 'wrong_operation':
            receipt['operation_id'] = '0' * 64
        elif self.fault == 'wrong_before':
            receipt['before_sha256'] = {n: '0' * 64 for n in PROGRAMS}
        elif self.fault == 'wrong_after':
            receipt['after_sha256'] = {n: '0' * 64 for n in PROGRAMS}
        elif self.fault == 'false_rollback':
            receipt['outcome'] = 'rolled_back'
            receipt['after_sha256'] = dict(expected_current_sha256)
        elif self.fault == 'unknown_outcome':
            receipt['outcome'] = 'maybe_written'
        return receipt


class PairTests(unittest.TestCase):
    save_manifest = fixtures.Tests.save_manifest
    open = fixtures.Tests.open
    tearDown = fixtures.Tests.tearDown

    def setUp(self):
        fixtures.Tests.setUp(self)
        self.device = PairDevice(self.root / 'pair-device')
        self.device.transaction = self.journal

    def pairs(self):
        return [c for c in self.device.calls if c[0] == 'pair']

    def reset(self, suffix):
        self.journal = self.root / ('transaction-' + suffix)
        self.device.transaction = self.journal
        self.device.calls = []
        self.device.fault = None
        for n in PROGRAMS:
            (self.device.root / n).write_bytes(BASE[n])

    def test_pair_install_restore_one_invocation_per_operation(self):
        with self.open() as t:
            result = t.install(self.device)
            self.assertEqual(result['current_sha256'], {n: digest(NEW[n]) for n in PROGRAMS})
            self.assertEqual(t.state['phase'], 'INSTALL_READBACK_VERIFIED')
            self.assertEqual(len(self.pairs()), 1)
            self.assertEqual(t.state['events'][1]['phase'], 'INSTALL_PAIR_WRITE_INTENT')
            t.restore(self.device, t.inspect(self.device))
            self.assertEqual(t.state['phase'], 'RESTORE_READBACK_VERIFIED')
            self.assertEqual(len(self.pairs()), 2)
            self.assertNotEqual(self.pairs()[0][1], self.pairs()[1][1])
            self.assertTrue(all(e['write_scope'] == 'pair' for e in t.state['events']))

    def test_faults_stop_without_retry_and_allow_inspected_restore(self):
        faults = ['before', 'partial_0', 'partial_1', 'after_0', 'after_1',
                  'interrupt_0', 'interrupt_1', 'corrupt_after_receipt',
                  'missing_receipt', 'wrong_operation', 'wrong_before', 'wrong_after',
                  'false_rollback', 'unknown_outcome']
        for fault in faults:
            with self.subTest(fault=fault):
                self.reset(fault)
                self.device.fault = fault
                with self.open() as t:
                    with self.assertRaises((OSError, Rejected, KeyboardInterrupt)):
                        t.install(self.device)
                    self.assertEqual(t.state['phase'], 'NEEDS_REVIEW')
                    self.assertEqual(len(self.pairs()), 1)
                with self.open() as t:
                    with self.assertRaises(Rejected):
                        t.install(self.device)
                    self.assertEqual(len(self.pairs()), 1)
                    self.device.fault = None
                    t.restore(self.device, t.inspect(self.device))
                    self.assertEqual(t.state['phase'], 'RESTORE_READBACK_VERIFIED')
                self.assertEqual({n: self.device.read_program(n) for n in PROGRAMS}, BASE)

    def test_native_rollback_or_prewrite_reject_is_not_install_success(self):
        for fault in ('rolled_back', 'rejected_before_write'):
            with self.subTest(fault=fault):
                self.reset(fault)
                self.device.fault = fault
                with self.open() as t:
                    with self.assertRaises(Rejected):
                        t.install(self.device)
                    self.assertEqual(t.state['phase'], 'NEEDS_REVIEW')
                    receipts = [e for e in t.state['events'] if e['phase'] == 'INSTALL_PAIR_RECEIPT_VERIFIED']
                    self.assertEqual(receipts[0]['outcome'], fault)
                    self.assertEqual({n: self.device.read_program(n) for n in PROGRAMS}, BASE)
                    self.device.fault = None
                    t.restore(self.device, t.inspect(self.device))
                    self.assertEqual(len(self.pairs()), 1)  # already baseline; no second mutation

    def test_native_preflight_closes_host_check_race(self):
        self.device.fault = 'source_changed_at_native_entry'
        with self.open() as t, self.assertRaises(Rejected):
            t.install(self.device)
        self.assertEqual(self.device.read_program(PROGRAMS[0]), BASE[PROGRAMS[0]])
        self.assertEqual(self.device.read_program(PROGRAMS[1]), b'concurrent-change')

    def test_pair_scope_cannot_change_to_per_file(self):
        with self.open() as t:
            t.install(self.device)
            inspection = t.inspect(self.device)
            self.device.calls = []
            self.device.write_scope = 'program'
            with self.assertRaises(Rejected):
                t.inspect(self.device)
            with self.assertRaises(Rejected):
                t.restore(self.device, inspection)
            self.assertEqual(self.device.calls, [])

    def test_stale_pair_restore_inspection_never_invokes_worker(self):
        with self.open() as t:
            t.install(self.device)
            inspection = t.inspect(self.device)
            (self.device.root / PROGRAMS[0]).write_bytes(b'changed-after-inspection')
            with self.assertRaises(Rejected):
                t.restore(self.device, inspection)
            self.assertEqual(len(self.pairs()), 1)

    def test_unreleased_pair_package_never_accesses_device(self):
        self.manifest['readiness']['status'] = 'NOT_READY_TO_FLASH'
        self.save_manifest()
        with self.open() as t, self.assertRaises(Rejected):
            t.install(self.device)
        self.assertEqual(self.device.calls, [])

    def test_pair_hardware_adapter_gate_precedes_identity(self):
        self.device.kind = 'hardware'
        with self.open() as t, self.assertRaises(Rejected):
            t.install(self.device)
        self.assertEqual(self.device.calls, [])

    def test_failed_pair_restore_requires_another_fresh_inspection(self):
        with self.open() as t:
            t.install(self.device)
            inspection = t.inspect(self.device)
            self.device.fault = 'after_0'
            with self.assertRaises(OSError):
                t.restore(self.device, inspection)
            self.assertEqual(t.state['phase'], 'NEEDS_REVIEW')
            self.assertEqual(len(self.pairs()), 2)
        self.device.fault = None
        with self.open() as t:
            with self.assertRaises(Rejected):
                t.restore(self.device, inspection)
            self.assertEqual(len(self.pairs()), 2)
            t.restore(self.device, t.inspect(self.device))
            self.assertEqual(len(self.pairs()), 3)
            self.assertEqual(t.state['phase'], 'RESTORE_READBACK_VERIFIED')
        self.assertEqual({n: self.device.read_program(n) for n in PROGRAMS}, BASE)

    def test_death_after_verified_receipt_is_recoverable_but_not_retryable(self):
        script = '''
import os, sys
from pathlib import Path
from test_pair_transaction import PairDevice, IDENTITY
from install_transaction import Package, Transaction
class DiesAfterReceipt(Transaction):
    def record(self, phase, **details):
        super().record(phase, **details)
        if phase == 'INSTALL_PAIR_RECEIPT_VERIFIED':
            os._exit(78)
d = object.__new__(PairDevice)
d.root, d.transaction = Path(sys.argv[2]), Path(sys.argv[3])
d.target, d.calls, d.fault = IDENTITY, [], sys.argv[4]
with DiesAfterReceipt(Package(sys.argv[1]), d.transaction) as t:
    t.install(d)
'''
        for outcome in ('written', 'rolled_back'):
            self.reset('receipt-' + outcome)
            result = subprocess.run([sys.executable, '-c', script, str(self.package_root),
                                     str(self.device.root), str(self.journal), outcome],
                                    cwd=Path(__file__).resolve().parent, capture_output=True)
            self.assertEqual(result.returncode, 78, result.stderr)
            with self.open() as t:
                self.assertEqual(t.state['phase'], 'INSTALL_PAIR_RECEIPT_VERIFIED')
                with self.assertRaises(Rejected):
                    t.install(self.device)
                t.restore(self.device, t.inspect(self.device))
                self.assertEqual(t.state['phase'], 'RESTORE_READBACK_VERIFIED')
            self.assertEqual({n: self.device.read_program(n) for n in PROGRAMS}, BASE)

    def test_pair_process_death_preserves_both_file_intent(self):
        script = '''
import sys
from pathlib import Path
from test_pair_transaction import PairDevice, IDENTITY
from install_transaction import Package, Transaction
d = object.__new__(PairDevice)
d.root, d.transaction = Path(sys.argv[2]), Path(sys.argv[3])
d.target, d.calls, d.fault = IDENTITY, [], sys.argv[4]
with Transaction(Package(sys.argv[1]), d.transaction) as t:
    t.install(d)
'''
        for index in (0, 1):
            self.reset('death-' + str(index))
            result = subprocess.run([sys.executable, '-c', script, str(self.package_root),
                                     str(self.device.root), str(self.journal), 'death_' + str(index)],
                                    cwd=Path(__file__).resolve().parent, capture_output=True)
            self.assertEqual(result.returncode, 77, result.stderr)
            with self.open() as t:
                self.assertEqual(t.state['phase'], 'INSTALL_PAIR_WRITE_INTENT')
                self.assertEqual(set(t.state['events'][-1]['target_sha256']), set(PROGRAMS))
                with self.assertRaises(Rejected):
                    t.install(self.device)
                self.assertEqual(self.pairs(), [])
                t.restore(self.device, t.inspect(self.device))
                self.assertEqual(t.state['phase'], 'RESTORE_READBACK_VERIFIED')
            self.assertEqual({n: self.device.read_program(n) for n in PROGRAMS}, BASE)


if __name__ == '__main__':
    unittest.main(verbosity=2)
