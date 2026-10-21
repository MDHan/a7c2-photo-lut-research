"""Rebuild, restore and audit dev-menu-02 offline; never release for flashing."""
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import build as b
import build_dynamic_menu as dynamic
import verify
from restore_baseline import restore


def main():
    folder = b.HERE / 'dev-menu-02'
    manifest = json.loads((folder / 'manifest.json').read_text())
    structural = verify.structural(folder, manifest)
    for source in manifest['build_sources']:
        assert b.sha((b.HERE / source['source']).read_bytes()) == source['sha256']
    with tempfile.TemporaryDirectory(prefix='lut-dynamic-audit-') as directory:
        temp = Path(directory)
        rebuilt = dynamic.build(temp / 'rebuilt')
        assert rebuilt['outputs'] == manifest['outputs'] and rebuilt['patches'] == manifest['patches']
        assert restore(folder, temp / 'restored') == b.HASHES
    scripts = ('verify.py', 'verify_menu.py', 'verify_dynamic_menu.py', 'verify_rule_relocations.py')
    for script in scripts:
        result = subprocess.run([sys.executable, str(b.HERE / script), str(folder)],
                                text=True, capture_output=True, check=True)
        (folder / (script + '.log')).write_text(result.stdout + result.stderr)
        print(script + ' passed', flush=True)
    reports = {name: json.loads((folder / name).read_text()) for name in
               ('verification.json', 'menu-verification.json', 'dynamic-menu-verification.json',
                'menu-relocation-verification.json')}
    rules = reports['dynamic-menu-verification.json']
    assert rules['target_evaluator_changes'] == 16
    assert len(rules['menu_to_native_exclusion_writeback_to_task_message']) == 32
    report = {
        'status': 'NOT_READY_TO_FLASH', 'audited_at_utc': datetime.now(timezone.utc).isoformat(),
        'camera_io': False, 'candidate': 'offline-v0.5/dev-menu-02',
        'candidate_sha256': {k: v['sha256'] for k, v in manifest['outputs'].items()},
        'structural': structural, 'rebuild_byte_identical': True, 'local_inverse_patch_verified': True,
        'dynamic_menu': {'target_evaluator_changes': 16,
                         'unaffected_evaluator_cases': rules['unaffected_evaluator_cases'],
                         'other_constraint_comparisons': rules['other_constraint_comparisons'],
                         'menu_exclusion_writeback_task_message_cases': 32,
                         'nonzero_load_bias_evaluator_cases': reports['menu-relocation-verification.json']['native_evaluator_cases'],
                         'inhibition_reference_counting_and_native_callbacks_verified': True,
                         'full_event_loop_verified': False, 'persistence_verified': False},
        'firmware_scope': 'Six additional AP data/relocation windows relative to dev-menu-01. CP unchanged.',
        'blockers': ['Complete menu event dispatch, import/binding/edit/delete flow and LUT upload ordering unverified.',
                     'Still/movie independent settings, save/load, cold start and MR recall unverified.',
                     'CP ownership across capture, cancellation, late callbacks and resource release remain unresolved.',
                     'Hardware installer adapter, native flush, settings preservation and device recovery incomplete.',
                     'No actual camera boot, preview/playback, or full-size JPEG pixel validation.'],
        'tests': {name: b.sha((folder / name).read_bytes()) for name in reports},
        'test_sources': {name: b.sha((b.HERE / name).read_bytes()) for name in (*scripts, Path(__file__).name)},
    }
    assert verify.structural(folder, manifest) == structural
    (folder / 'readiness.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'dynamic_menu', 'rebuild_byte_identical')}, indent=2))


if __name__ == '__main__':
    main()
