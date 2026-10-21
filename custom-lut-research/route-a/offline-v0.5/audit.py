"""Offline preflash audit. Never imports or runs a camera adapter.

Pass means the stated assertions hold, not that the firmware is flash-ready.
Existing native tests are rerun; new cases cover dynamic option callbacks,
movie constructors, the feature-0xa2 branch, and unregistered LUT slots.
"""
import importlib.util
import itertools
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import build as b
import verify as v
from verify_menu import Native, RAM, OPTIONS

HERE = Path(__file__).resolve().parent


def rebuild_and_restore(folder, manifest):
    from restore_baseline import restore
    with tempfile.TemporaryDirectory(prefix='offline-lut-audit-') as temp:
        root = Path(temp)
        rebuilt = b.build(root / 'rebuilt')
        assert rebuilt['outputs'] == manifest['outputs']
        assert rebuilt['patches'] == manifest['patches']
        restored = restore(folder, root / 'restored')
        assert restored == b.HASHES
    return {'recompiled_images_byte_identical': True,
            'local_restore_output_matches_fl23_baseline': True,
            'device_restore_executed': False}


def main():
    folder = HERE / 'dev-menu-01'
    out = HERE / 'preflash-audit'
    out.mkdir(exist_ok=True)
    manifest = json.loads((folder / 'manifest.json').read_text())
    hashes = {n: b.sha((folder / 'candidate' / n).read_bytes()) for n in manifest['outputs']}
    report = {'status': 'NOT_READY_TO_FLASH', 'camera_io': False,
              'audited_at_utc': datetime.now(timezone.utc).isoformat(),
              'candidate': 'offline-v0.5/dev-menu-01', 'candidate_sha256': hashes,
              'structural': v.structural(folder, manifest)}
    for source in manifest['build_sources']:
        assert b.sha((HERE / source['source']).read_bytes()) == source['sha256']
    report['build_sources_match_manifest'] = True
    report['rebuild_and_local_restore'] = rebuild_and_restore(folder, manifest)
    for name in ('verify.py', 'verify_menu.py'):
        completed = subprocess.run([sys.executable, str(HERE / name), str(folder)],
                                   text=True, capture_output=True, check=True)
        (out / (name + '.log')).write_text(completed.stdout + completed.stderr)
        print(name + ' passed', flush=True)
    baseline = (b.BASE / 'appFw.so').read_bytes()
    candidate = (folder / 'candidate/appFw.so').read_bytes()
    old, new = Native(baseline), Native(candidate)
    callbacks = []
    for profile, inhibit in itertools.product(range(12, 16), (0, 1)):
        values = []
        for native in (old, new):
            callback = native.qword(OPTIONS + profile * 0xb8 + 0x98)
            metadata = native.run(0x28696b0)
            native.write(metadata + 0x15 + profile, bytes([inhibit]))
            value = native.run(callback, allowed=((0x1bb9718, 0x1bb97f8),))
            assert value == inhibit
            values.append(value)
        callbacks.append({'profile': profile, 'supplied_inhibit_flag': inhibit,
                          'baseline': values[0], 'candidate': values[1]})
    report['dynamic_option_callbacks'] = {
        'cases': callbacks,
        'runtime_availability_recomputation_proven': False,
        'interpretation': 'Native callbacks echo the supplied inhibition byte; 1 means an active restriction. '
                          'The counter-to-byte relation is separately executed by verify_dynamic_menu.py. '
                          'This older callback test supplies the byte and does not run the event loop.'}
    movie = feature = missing = 0
    for flag, entry, profile, lut, exists in itertools.product(
            (0, 1), (0x311a63c, 0x311a88c), range(12, 16), (3, 18), (0, 1)):
        old.feature_a2 = new.feature_a2 = flag
        before = old.task(entry, 3, profile, lut, exists)
        after = new.task(entry, 3, profile, lut, exists)
        assert before == after == (lut, exists)
        assert old.u.mem_read(RAM + 0x4000, 0x80) == new.u.mem_read(RAM + 0x4000, 0x80)
        if entry == 0x311a88c:
            assert old.send_base_task() == new.send_base_task()
        movie += 1
    for flag, profile, lut, exists in itertools.product((0, 1), range(12, 16), range(3, 19), (0, 1)):
        new.feature_a2 = flag
        assert new.task(0x311a88c, 2, profile, lut, exists) == (lut, exists)
        # Native feature flag A2 forces the still input field to 1. Missing
        # slots independently select the native fallback input field of 1.
        expected_input = int(flag == 1 or exists == 0)
        assert new.word(RAM + 0x4000 + 0x24) == expected_input
        message = new.send_base_task()
        if exists:
            assert message == [10, 0, expected_input, 1, 0], message
        else:
            assert message[:2] == [11, 3], message
            missing += 1
        feature += 1
    report['additional_setting_checks'] = {
        'movie_constructor_differential_cases': movie,
        'still_feature_a2_and_slot_cases': feature,
        'unregistered_slot_message_cases': missing,
        'actual_mode_switch_events_executed': False,
        'scope': 'Supplied model state; real native constructors and sender; captured transport.'}
    # Reuse our read-only audit helpers. This module has no camera imports;
    # importing it does not run its main or the old firmware verifier.
    helper = HERE.parent / 'offline-v0.4/preflash-audit-20261018/check.py'
    spec = importlib.util.spec_from_file_location('previous_offline_audit', helper)
    prior = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prior)
    report['local_backups'] = prior.backups()
    report['installer'] = prior.installer()
    report['installer']['current_candidate_supported'] = False
    completed = subprocess.run([sys.executable, str(HERE / 'verify_installer.py')],
                               text=True, capture_output=True, check=True)
    (out / 'verify_installer.py.log').write_text(completed.stdout + completed.stderr)
    transaction = json.loads((HERE / 'installer-evidence/verification.json').read_text())
    assert transaction['candidate_sha256'] == hashes
    assert transaction['camera_io'] is False and transaction['device_methods_invoked'] == []
    assert transaction['actual_candidate_release_gate'] == 'REJECTED_BEFORE_DEVICE_ACCESS'
    assert transaction['candidate_flash_ready'] is False
    report['candidate_install_transaction'] = transaction
    print('verify_installer.py passed; actual candidate remains blocked', flush=True)
    completed = subprocess.run([sys.executable, str(HERE / 'verify_menu_rules.py')],
                               text=True, capture_output=True, check=True)
    (out / 'verify_menu_rules.py.log').write_text(completed.stdout + completed.stderr)
    rules = json.loads((out / 'menu-rule-verification.json').read_text())
    assert rules['candidate_sha256'] == hashes['appFw.so']
    report['native_menu_rule_selection'] = rules
    print('verify_menu_rules.py passed; full dynamic availability remains unverified', flush=True)
    cp = (folder / 'candidate/cpapp-b.bin').read_bytes()
    report['native_loader_fault_injection'] = prior.early_load_failure(cp, manifest)
    report['fault_injection_limit'] = (
        'Channel lookup failure is explicitly injected. This is not evidence '
        'that normal valid-group operation fails or that outer cleanup leaks.')
    # Preserve original disassembly as review evidence; do not interpret a
    # diagnostic dump at the failure destination as a release function.
    import binary_queries as q
    assert cp[0x4a51ec - 0x108000:0x4a54a4 - 0x108000] == q.CP[0x4a51ec - 0x108000:0x4a54a4 - 0x108000]
    (out / 'native_failure_diagnostic.txt').write_text(q.disasm('cp', 0x4a51ec, 0x4a54a4))
    report['blockers'] = [
        'Dynamic menu constraints and event dispatch have not been validated end to end.',
        'LUT upload scheduling, still/movie persistence, cold start and MR recall are unverified.',
        'Capture-long resource ownership, buffer lifetime and asynchronous failure recovery are unresolved.',
        'Offline candidate install/readback/restore transaction passed fault tests; hardware adapter, native flush and settings preservation remain unimplemented or unverified. Existing installer accepts old FL23 only.',
    ]
    report['hardware_validation_pending'] = ['Boot', 'LUT pixels in full-size JPEG', 'Preview and playback',
                                              'Recovery after cancellation or error']
    menu = json.loads((folder / 'menu-verification.json').read_text())
    report['menu_summary'] = {k: len(menu[k]) for k in
                              ('menu_gates', 'task_cases', 'task_to_ap_message', 'menu_commit_cases')}
    report['menu_summary']['context_cases'] = menu['context_cases']
    assert hashes == {n: b.sha((folder / 'candidate' / n).read_bytes()) for n in hashes}
    report['candidate_unchanged'] = True
    report['audit_script_sha256'] = b.sha(Path(__file__).read_bytes())
    report['helper_script_sha256'] = b.sha(helper.read_bytes())
    report['test_reports_sha256'] = {n: b.sha((folder / n).read_bytes()) for n in
                                    ('verification.json', 'menu-verification.json')}
    (out / 'readiness.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'menu_summary', 'additional_setting_checks',
                                             'local_backups', 'candidate_unchanged')}, indent=2))


if __name__ == '__main__':
    main()
