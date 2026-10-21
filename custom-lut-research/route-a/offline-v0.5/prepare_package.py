"""Prepare a private, manifest-bound local package without importing USB code."""
import argparse
import json
import os
from pathlib import Path

import build
from install_transaction import PROGRAMS, Package, atomic_json, canonical, digest, require


def prepare(candidate, readiness, identity, output):
    candidate, readiness, identity, output = map(Path, (candidate, readiness, identity, output))
    manifest_raw = (candidate / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_raw)
    review_raw = readiness.read_bytes()
    review = json.loads(review_raw)
    require(manifest['inputs'] == build.HASHES, 'Unsupported firmware baseline')
    require(set(manifest['outputs']) == set(PROGRAMS), 'Incomplete AP/CP pair')
    require(review['candidate_sha256'] == {n: manifest['outputs'][n]['sha256'] for n in PROGRAMS},
            'Review is for a different candidate pair')
    data, programs = {}, {}
    for name in PROGRAMS:
        original = (build.BASE / name).read_bytes()
        modified = (candidate / 'candidate' / name).read_bytes()
        require(digest(original) == build.HASHES[name], 'Baseline file mismatch')
        require(digest(modified) == manifest['outputs'][name]['sha256'] and
                len(modified) == manifest['outputs'][name]['size'], 'Candidate file mismatch')
        undo = bytearray(modified)
        for patch in manifest['patches']:
            if patch['file'] == name:
                begin, size = patch['offset'], patch['length']
                require(undo[begin:begin + size] == bytes.fromhex(patch['after']), 'Patch manifest mismatch')
                undo[begin:begin + size] = bytes.fromhex(patch['before'])
        require(bytes(undo) == original, 'Candidate includes undeclared changes')
        data[name] = {'baseline': original, 'candidate': modified}
        programs[name] = {role: {'sha256': digest(raw), 'size': len(raw)} for role, raw in data[name].items()}
    for source in manifest['build_sources']:
        require(Path(source['source']).name == source['source'], 'Invalid source filename')
        require(digest((build.HERE / source['source']).read_bytes()) == source['sha256'], 'Source changed after build')
    target = json.loads(identity.read_text())
    require(isinstance(target, dict) and bool(target), 'Missing target identity')
    package = {'format': 1, 'programs': programs, 'identity_sha256': digest(canonical(target)),
               'target': manifest['target'], 'firmware_manifest_sha256': digest(manifest_raw),
               'readiness_report_sha256': digest(review_raw),
               'readiness': {'status': review['status'], 'candidate_sha256': review['candidate_sha256']},
               'hardware_adapter_available': False,
               'restore_scope': 'Exact previous FL23 program pair; not stock firmware or settings restore'}
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for role in ('baseline', 'candidate'):
        directory = output / role
        directory.mkdir(mode=0o700)
        for name in PROGRAMS:
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data[name][role])
                stream.flush()
                os.fsync(stream.fileno())
    atomic_json(output / 'package.json', package)
    checked = Package(output)
    return {'package': str(output), 'package_sha256': checked.key,
            'readiness': review['status'], 'hardware_adapter_available': False, 'camera_io': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--readiness', type=Path, required=True)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.candidate, args.readiness, args.identity, args.output), indent=2))
