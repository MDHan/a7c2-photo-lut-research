"""Record offline installer tests and verify the actual candidate stays blocked."""
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from install_transaction import Package, Transaction, Rejected, digest

HERE = Path(__file__).resolve().parent


class ForbiddenDevice:
    kind = 'hardware'

    def __init__(self):
        self.calls = []

    def identity(self):
        self.calls.append('identity')
        raise AssertionError('Device access is prohibited in this verifier')

    def read_program(self, name):
        self.calls.append('read')
        raise AssertionError('Device access is prohibited in this verifier')

    def write_program(self, name, raw):
        self.calls.append('write')
        raise AssertionError('Device access is prohibited in this verifier')

    def write_pair(self, *args, **kwargs):
        self.calls.append('write_pair')
        raise AssertionError('Device access is prohibited in this verifier')


def main():
    result = subprocess.run([sys.executable, '-m', 'unittest', '-v',
                             'test_install_transaction', 'test_pair_transaction'],
                            cwd=HERE, text=True, capture_output=True, check=True)
    out = HERE / 'installer-evidence'
    out.mkdir(exist_ok=True)
    (out / 'tests.log').write_text(result.stdout + result.stderr)
    package = Package(HERE / 'package-dev-menu-01')
    device = ForbiddenDevice()
    with tempfile.TemporaryDirectory(prefix='lut-install-gate-') as temp:
        with Transaction(package, Path(temp) / 'transaction') as t:
            try:
                t.install(device)
            except Rejected as error:
                assert str(error) == 'Candidate is not released for controlled flashing', str(error)
            else:
                raise AssertionError('Unreleased actual candidate was accepted')
            assert t.state['phase'] == 'NEW' and device.calls == []
        latest = Package(HERE / 'package-dev-menu-02')
        paired_device = ForbiddenDevice()
        paired_device.write_scope = 'pair'
        with Transaction(latest, Path(temp) / 'pair-transaction') as t:
            try:
                t.install(paired_device)
            except Rejected as error:
                assert str(error) == 'Candidate is not released for controlled flashing', str(error)
            else:
                raise AssertionError('Unreleased paired candidate was accepted')
            assert t.state['phase'] == 'NEW' and paired_device.calls == []
    report = {'status': 'OFFLINE_TRANSACTION_CORE_VERIFIED_HARDWARE_ADAPTER_MISSING',
              'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'camera_io': False,
              'package_sha256': package.key, 'candidate_sha256': package.expected('candidate'),
              'baseline_sha256': package.expected('baseline'),
              'actual_candidate_release_gate': 'REJECTED_BEFORE_DEVICE_ACCESS',
              'candidate_flash_ready': False, 'device_methods_invoked': device.calls,
              'latest_pair_package': {'package_sha256': latest.key,
                                      'candidate_sha256': latest.expected('candidate'),
                                      'release_gate': 'REJECTED_BEFORE_DEVICE_ACCESS',
                                      'device_methods_invoked': paired_device.calls},
              'fault_tests': ['AP and CP write failure before, partial, corrupt, after, and interrupt',
                              'Actual subprocess death after AP or CP write', 'Persisted intent before mutation',
                              'No automatic retry after reopening journal', 'Fresh inspection before explicit restore',
                              'Stale recovery inspection, wrong identity and wrong baseline rejection',
                              'Paired candidate integrity, single writer lock and backend-kind isolation',
                              'One native pair invocation with durable two-file intent and operation-bound receipt',
                              '14 native pair fault/receipt cases, verified rollback and prewrite rejection',
                              'Pair process death after AP or CP; no per-file fallback or automatic retry',
                              'Pair process death after written/rolled-back receipt; interrupted restore needs fresh inspection',
                              'Pair/program scope isolation and native source-pair recheck contract'],
              'not_proven': ['Native file replacement and flush', 'Camera service session and permissions',
                             'Native install preflight', 'Settings preservation', 'Camera cold start',
                             'Unbootable device recovery'],
              'sources': {n: digest((HERE / n).read_bytes()) for n in
                          ('install_transaction.py', 'prepare_package.py', 'test_install_transaction.py', 'test_pair_transaction.py',
                           'verify_installer.py')},
              'test_log_sha256': digest((out / 'tests.log').read_bytes())}
    (out / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'camera_io', 'actual_candidate_release_gate',
                                             'candidate_flash_ready')}, indent=2))


if __name__ == '__main__':
    main()
