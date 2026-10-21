"""Check the actual Git index (or a clean source tree) before publication."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {'.py', '.c', '.h', '.S', '.md', '.json', '.yml', '.yaml', '.txt'}
SPECIAL = {'LICENSE', '.gitignore'}
FORBIDDEN_PARTS = {'candidate', 'original', 'readback', 'private-inputs', 'lifecycle-dev', '__pycache__'}
PATTERNS = [
    ('personal home path', re.compile('/' + r'(?:Users|home)/[^\s/]+/')),
    ('credential', re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{30,}|sk-proj-[A-Za-z0-9_-]{25,})')),
    ('private key', re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----')),
]

def check_file(name, data):
    p = Path(name)
    problems = []
    if p.is_absolute() or '..' in p.parts:
        problems.append('non-relative path')
    if any(x in FORBIDDEN_PARTS or x.startswith(('backup-', 'install-', 'package-dev-')) for x in p.parts):
        problems.append('private/generated directory')
    if '.private.' in p.name or p.name.startswith('.') and p.name not in SPECIAL and p.name != '.gitkeep':
        problems.append('private/hidden file')
    if p.suffix not in ALLOWED and p.name not in SPECIAL:
        problems.append('unexpected file type')
    if len(data) > 2_000_000:
        problems.append('unexpected large file')
    try:
        text = data.decode('utf-8')
        if '\0' in text:
            problems.append('binary/NUL data')
        problems += [label for label, pattern in PATTERNS if pattern.search(text)]
        if p.suffix == '.json':
            record = json.loads(text)
            if isinstance(record, dict) and any(k in record for k in ('patches', 'patch_windows', 'serial_number', 'serialNumber')):
                problems.append('raw patch/identity record')
    except (UnicodeError, json.JSONDecodeError):
        problems.append('invalid text/JSON')
    return problems

def records(tracked):
    if tracked:
        result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT, check=True, capture_output=True)
        names = [s for s in result.stdout.decode().split('\0') if s]
        if not names:
            raise RuntimeError('No staged/tracked files to review')
        entries = {}
        for name in names:
            entries[name] = subprocess.run(['git', 'show', ':' + name], cwd=ROOT, check=True, capture_output=True).stdout
        return entries
    return {str(p.relative_to(ROOT)): p.read_bytes() for p in ROOT.rglob('*')
            if p.is_file() and not any(x in ('.git', '.venv') for x in p.relative_to(ROOT).parts)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tracked', action='store_true', help='inspect index bytes, not just the working tree')
    args = parser.parse_args()
    entries = records(args.tracked)
    errors = {name: check_file(name, data) for name, data in entries.items()}
    errors = {name: values for name, values in errors.items() if values}
    snapshot = json.loads(entries['evidence/source-snapshot.json'])
    for item in snapshot['files']:
        if item['path'] not in entries or hashlib.sha256(entries[item['path']]).hexdigest() != item['sha256']:
            errors.setdefault(item['path'], []).append('source snapshot mismatch')
    evidence = json.loads(entries['evidence/dev-events-05-summary.json'])
    if evidence['status'] != 'NOT_READY_TO_FLASH' or evidence['camera_io'] is not False or evidence['firmware_included'] is not False:
        errors['evidence/dev-events-05-summary.json'] = ['evidence boundary changed']
    print(json.dumps({'checked': 'git-index' if args.tracked else 'source-tree', 'files': len(entries), 'errors': errors}, indent=2))
    if errors:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
