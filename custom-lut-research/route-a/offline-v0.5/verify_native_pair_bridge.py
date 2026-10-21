"""Record the host/C bridge tests and generated-plan execution on private copies."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from install_transaction import Package, PROGRAMS, canonical, digest
from native_pair_backend import FixedWindows
from native_pair_report import decode_receipt
from test_native_pair_bridge import LocalSession

HERE = Path(__file__).resolve().parent


def main():
    source_names = ('install_transaction.py', 'native_pair_backend.py', 'native_pair_report.py', 'native_write_order.py',
                    'native/pair_core.c', 'native/pair_core.h', 'native/sha256.h',
                    'test_native_pair_core.py', 'test_native_pair_bridge.py', 'verify_native_pair_bridge.py')
    sources = {n: digest((HERE / n).read_bytes()) for n in source_names}
    out = HERE / 'installer-evidence'
    result = subprocess.run([sys.executable, str(HERE / 'test_native_pair_bridge.py')],
                            capture_output=True, text=True, check=True)
    log = result.stdout + result.stderr
    assert 'Ran 9 tests' in log and '\nOK\n' in log
    (out / 'native-bridge-tests.log').write_text(log)
    package = Package(HERE / 'package-dev-menu-02')
    manifest = (HERE / 'dev-menu-02/manifest.json').read_bytes()
    fixed = FixedWindows(package, manifest)
    before = {n: package.files[n]['baseline'] for n in PROGRAMS}
    target = {n: package.files[n]['candidate'] for n in PROGRAMS}
    operation = digest(b'OFFLINE_GENERATED_PLAN_TEST:' + package.key.encode())
    bundle = fixed.prepare(before, target, package.expected('baseline'), operation)
    assert bundle == fixed.prepare(before, target, package.expected('baseline'), operation)
    # Execute only against fresh temporary copies. This is a C plan fixture,
    # not a real-package Transaction.install call or release-gate override.
    with tempfile.TemporaryDirectory(prefix='lut-generated-full-pair-') as directory:
        root = Path(directory)
        journal = root / 'fixture-journal'
        journal.mkdir()
        (journal / 'journal.json').write_bytes(canonical({
            'phase': 'INSTALL_PAIR_WRITE_INTENT',
            'events': [{'operation_id': operation, 'expected_current_sha256': package.expected('baseline'),
                        'target_sha256': package.expected('candidate')}]}))
        session = LocalSession(root / 'fixture-files', [before[n] for n in PROGRAMS], journal)
        inodes = [p.stat().st_ino for p in session.files.paths]
        raw = session.run_native(bundle)
        receipt = decode_receipt(raw, operation, package.expected('baseline'), package.expected('candidate'))
        assert receipt['outcome'] == 'written'
        assert {n: session.read_program(n) for n in PROGRAMS} == target
        assert [p.stat().st_ino for p in session.files.paths] == inodes
    assert sources == {n: digest((HERE / n).read_bytes()) for n in source_names}
    report = {
        'status': 'HOST_NATIVE_BRIDGE_VERIFIED_CAMERA_SESSION_MISSING',
        'camera_io': False, 'candidate_flash_ready': False, 'sources': sources,
        'test_log_sha256': digest(log.encode()), 'host_native_bridge_tests': 9,
        'actual_generated_plan_fixture': {'package_sha256': package.key,
                                          'candidate_sha256': package.expected('candidate'),
                                          'bundle_sha256': bundle.sha256,
                                          'header_sha256': digest(bundle.header),
                                          'window_count': len(fixed.windows),
                                          'full_file_bytes_equal_candidate': True,
                                          'inode_preserved': True,
                                          'real_package_release_gate_overridden': False},
        'verified': ['Manifest/package hash binding and exact inverse-patch boundaries',
                     'Operation-specific immutable C preimage/target plan generation',
                     'Host journal through generated C plan, binary report and independent readback',
                     'Native rollback, lost/stale report and changed host readback stop without retry',
                     'Fresh partial-window recovery; outside-window corruption rejected before native invocation'],
        'not_verified': ['Camera native session and fixed-path syscall implementation',
                         'Linked AArch64 module loading and report transfer',
                         'Real mount/process exclusivity, settings, WBI and boot']}
    (out / 'native-bridge-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'camera_io', 'host_native_bridge_tests',
                                           'actual_generated_plan_fixture')}, indent=2))


if __name__ == '__main__':
    main()
