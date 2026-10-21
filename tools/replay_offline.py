"""Rebuild and verify from privately supplied exact inputs, without device APIs.

Copies only appFw.so and cpapp-b.bin to the ignored historical compatibility
path, retaining the original research sources byte-for-byte. Never downloads
firmware, enumerates USB, installs to a camera, or imports a camera adapter.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / 'custom-lut-research/route-a/offline-v0.5'
COMPAT = ROOT / 'install-20261018-085012/candidate'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def exact_existing(folder, expected):
    return all((folder / n).is_file() and sha(folder / n) == h for n, h in expected.items())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True, help='private directory containing the exact existing FL2/FL3 baseline pair')
    args = parser.parse_args()
    fingerprints = json.loads((ROOT / 'evidence/input-fingerprints.json').read_text())['files']
    if not exact_existing(args.baseline, fingerprints):
        parser.error('Input pair is missing or mismatched; no output was changed. Read docs/REPRODUCING.md.')
    expected = json.loads((ROOT / 'evidence/dev-events-05-summary.json').read_text())['outputs_fingerprints_only']
    if COMPAT.exists() and not exact_existing(COMPAT, fingerprints):
        parser.error('Existing ignored compatibility inputs differ; refusing to overwrite.')
    COMPAT.mkdir(parents=True, exist_ok=True)
    for name in fingerprints:
        destination = COMPAT / name
        if not destination.exists():
            shutil.copyfile(args.baseline / name, destination)
    sys.path.insert(0, str(RESEARCH))
    import build as base
    assert base.BASE == COMPAT
    (RESEARCH / 'lifecycle-dev').mkdir(exist_ok=True)
    two = RESEARCH / 'dev-menu-02'
    if not two.exists():
        import build_dynamic_menu
        build_dynamic_menu.build(two)
    assert exact_existing(two / 'candidate', {'appFw.so': 'a3bffb09002988c4873122b6db41a2e23c87c2a66ff82a2d53b0fdb6959f533d', 'cpapp-b.bin': '48ff01e346ac74e78b61f811725c0bd95ab2712938b55ad607a5b2f54a3bf4e1'})
    three = RESEARCH / 'dev-menu-03'
    if not three.exists():
        import build_upload_guards
        build_upload_guards.build(three)
    frozen = {'appFw.so': '5e0741cf58f4125f7b6f5950b5d13d47be025052c9dcc1a799e2ce004cd32c93', 'cpapp-b.bin': '48ff01e346ac74e78b61f811725c0bd95ab2712938b55ad607a5b2f54a3bf4e1'}
    assert exact_existing(three / 'candidate', frozen)
    readiness = three / 'readiness.json'
    if not readiness.exists():
        # Minimal local input metadata, not a copied historical approval.
        readiness.write_text(json.dumps({'status': 'NOT_READY_TO_FLASH', 'camera_io': False, 'candidate_sha256': frozen, 'origin': 'locally regenerated private input pair'}, indent=2) + '\n')
    # The events sources deliberately retain the preceding upload-stage
    # generated header as a dependency. Generate it before compiling events.
    import build_lut_upload_cp
    build_lut_upload_cp.make()
    steps = ['verify_lut_events_integration.py', 'verify_lut_menu_events.py', 'verify_lut_events_readers.py', 'verify_lut_events_photo.py', 'build_lut_events_candidate.py']
    for name in steps:
        print('Offline step:', name, flush=True)
        subprocess.run([sys.executable, str(RESEARCH / name)], cwd=RESEARCH, check=True)
    output = RESEARCH / 'dev-events-05/candidate'
    actual = {n: sha(output / n) for n in expected}
    if actual != {n: v['sha256'] for n, v in expected.items()}:
        raise RuntimeError('Different candidate bytes: preserve outputs and investigate the compiler/source difference; do not reuse historical evidence.')
    validation = {'status': 'OFFLINE_REPLAY_PASSED_NOT_READY_TO_FLASH', 'camera_io': False, 'steps': steps, 'candidate_sha256': actual, 'compiler': subprocess.run(['/usr/bin/clang', '--version'], check=True, capture_output=True, text=True).stdout.splitlines()[0], 'python': sys.version.split()[0]}
    (ROOT / 'local-validation.json').write_text(json.dumps(validation, indent=2) + '\n')
    print(json.dumps(validation, indent=2))

if __name__ == '__main__':
    main()
