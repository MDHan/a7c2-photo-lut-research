"""Check complete-window dependencies and real C write order, strictly offline.

No assertion here covers a partially written instruction, power loss, live PCs,
instruction caches, already-loaded relocation data, or AP/CP activation.
"""
import argparse
import json
from pathlib import Path
import tempfile

from install_transaction import Package, PROGRAMS, canonical, digest
from native_pair_backend import FixedWindows
from native_pair_report import decode_receipt
from native_write_order import consumers_for
from test_native_pair_bridge import LocalSession

HERE = Path(__file__).resolve().parent


def violations(state, dependencies):
    return [(a, b) for a, b in dependencies if state[b] and not state[a]]


def apply_path(state, order, target, dependencies):
    """Model a complete window as old/new; not an atomic-write assertion."""
    states = [dict(state)]
    for file, offset, _ in order:
        state = dict(state)
        state[file, offset] = target
        states.append(state)
    return states, [violations(s, dependencies) for s in states]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', choices=('dev-menu-02', 'dev-menu-03'), default='dev-menu-02')
    args = parser.parse_args()
    names = ('native_write_order.py', 'native_pair_backend.py', 'native/pair_core.c',
             'native/pair_core.h', 'native/sha256.h', 'native_pair_report.py',
             'install_transaction.py', 'test_native_pair_core.py',
             'test_native_pair_bridge.py', 'verify_native_write_order.py')
    hashes = {n: digest((HERE / n).read_bytes()) for n in names}
    package = Package(HERE / ('package-' + args.candidate))
    fixed = FixedWindows(package, (HERE / args.candidate / 'manifest.json').read_bytes())
    consumers = consumers_for(package)
    old = {(f, at): False for f, at, _ in fixed.windows}
    new = dict.fromkeys(old, True)
    body_edges = [(body, entry) for entry, body in consumers.items()]
    old_states, old_hazards = apply_path(old, fixed.windows, True, body_edges)
    affected = sorted({entry for edges in old_hazards for _, entry in edges})
    assert set(affected) == set(consumers), 'Expected old-order regression was not reproduced'
    installed, hazards = apply_path(old, fixed.install_order, True, fixed.dependencies)
    assert not any(hazards)
    restored, hazards = apply_path(new, list(reversed(fixed.install_order)), False, fixed.dependencies)
    assert not any(hazards)
    assert installed[-1] == new and restored[-1] == old
    # The actual C engine rolls ALL windows back in reverse supplied order,
    # even when only an early prefix was written. Check every complete prefix.
    rollback_paths = 0
    for states, order, target, endpoint in (
            (installed, list(reversed(fixed.install_order)), False, old),
            (restored, fixed.install_order, True, new)):
        for state in states:
            path, hazards = apply_path(state, order, target, fixed.dependencies)
            assert not any(hazards) and path[-1] == endpoint
            rollback_paths += 1
    before = {n: package.files[n]['baseline'] for n in PROGRAMS}
    after = {n: package.files[n]['candidate'] for n in PROGRAMS}
    native_results = []
    with tempfile.TemporaryDirectory(prefix='lut-order-') as directory:
        root = Path(directory)
        journal = root / 'journal'
        journal.mkdir()
        session = LocalSession(root / 'files', [before[n] for n in PROGRAMS], journal)
        inodes = [p.stat().st_ino for p in session.files.paths]
        for action, source, target, order in (
                ('INSTALL', before, after, fixed.install_order),
                ('RESTORE', after, before, list(reversed(fixed.install_order)))):
            operation = digest(('OFFLINE_ORDER_' + action + ':' + package.key).encode())
            source_hashes = {n: digest(source[n]) for n in PROGRAMS}
            target_hashes = {n: digest(target[n]) for n in PROGRAMS}
            bundle = fixed.prepare(source, target, source_hashes, operation)
            metadata = json.loads(bundle.metadata)
            assert metadata['windows'] == [list(row) for row in order]
            assert metadata['live_patch_safety_verified'] is False
            (journal / 'journal.json').write_bytes(canonical({
                'phase': action + '_PAIR_WRITE_INTENT',
                'events': [{'operation_id': operation, 'expected_current_sha256': source_hashes,
                            'target_sha256': target_hashes}]}))
            session.files.events.clear()
            receipt = decode_receipt(session.run_native(bundle), operation, source_hashes, target_hashes)
            actual = [event[1:] for event in session.files.events if isinstance(event, tuple) and event[0] == 'write']
            assert actual == order, (action, actual, order)
            assert receipt['outcome'] == 'written'
            assert {n: session.read_program(n) for n in PROGRAMS} == target
            assert [p.stat().st_ino for p in session.files.paths] == inodes
            native_results.append({'action': action, 'bundle_sha256': bundle.sha256,
                                   'actual_write_callbacks': actual, 'full_bytes_verified': True})
    assert hashes == {n: digest((HERE / n).read_bytes()) for n in names}
    report = {'status': 'COMPLETE_WINDOW_ORDER_VERIFIED_LIVE_PATCH_UNVERIFIED',
              'camera_io': False, 'candidate_flash_ready': False,
              'package_sha256': package.key, 'candidate_sha256': package.expected('candidate'),
              'sources': hashes, 'window_count': len(fixed.windows),
              'old_order_branch_consumers_with_unwritten_body': affected,
              'install_and_restore_boundaries_checked': len(installed) + len(restored),
              'complete_prefix_rollback_paths_checked': rollback_paths,
              'native_execution': native_results,
              'limitations': ['Complete-window boundaries only; no atomic pwrite claim',
                              'Partial-window source may already violate dependencies',
                              'No power-loss persistence ordering or recovery guarantee',
                              'No live PC, cache, relocated data or AP/CP activation validation',
                              'Camera platform/session/module loader not implemented']}
    output = HERE / ('installer-evidence' if args.candidate == 'dev-menu-02' else args.candidate) / 'native-write-order-verification.json'
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'camera_io', 'window_count',
                     'old_order_branch_consumers_with_unwritten_body',
                     'install_and_restore_boundaries_checked', 'complete_prefix_rollback_paths_checked')}, indent=2))


if __name__ == '__main__':
    main()
