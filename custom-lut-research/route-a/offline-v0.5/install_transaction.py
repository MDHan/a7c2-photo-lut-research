"""AP/CP installation transaction core; no device discovery or USB imports.

A device adapter implements identity/read_program and declares write_scope:
"program" uses write_program; "pair" uses one write_pair call and a bound receipt.
There is deliberately no hardware adapter here yet. The journal reports full
readback, not boot, settings persistence or image-processing success.
"""
import fcntl
import hashlib
import json
import os
import tempfile
from pathlib import Path

PROGRAMS = ('appFw.so', 'cpapp-b.bin')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Rejected(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def atomic_json(path, data):
    """Persist intent before external writes, including rename metadata."""
    path = Path(path)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + '.', suffix='.new', dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(data) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temp.exists():
            temp.unlink()


class Package:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.manifest_bytes = (self.root / 'package.json').read_bytes()
        self.manifest = json.loads(self.manifest_bytes)
        m = self.manifest
        require(m['format'] == 1 and set(m['programs']) == set(PROGRAMS), 'Invalid package format/program pair')
        require(isinstance(m['identity_sha256'], str) and len(m['identity_sha256']) == 64, 'Missing target identity')
        self.files = {}
        for name in PROGRAMS:
            self.files[name] = {}
            for role in ('baseline', 'candidate'):
                path = self.root / role / name
                require(not path.is_symlink() and path.resolve().parent == self.root / role, 'Unexpected package file path')
                raw = path.read_bytes()
                spec = m['programs'][name][role]
                require(len(raw) == spec['size'] and digest(raw) == spec['sha256'], 'Package data mismatch: ' + name)
                self.files[name][role] = raw
        self.key = digest(self.manifest_bytes)

    def require_release(self):
        review = self.manifest['readiness']
        require(review['status'] == 'READY_FOR_CONTROLLED_FLASH', 'Candidate is not released for controlled flashing')
        require(review['candidate_sha256'] == self.expected('candidate'), 'Readiness report refers to a different pair')

    def expected(self, role):
        return {n: digest(self.files[n][role]) for n in PROGRAMS}


class Transaction:
    """Single writer; any uncertain write stops and needs fresh inspection.

    Recovery uses a separate, explicit operation with a digest of the freshly
    inspected complete pair. No failure causes automatic rollback or retry.
    """
    def __init__(self, package, root):
        self.package = package
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(self.root.stat().st_mode & 0o077 == 0, 'Transaction directory must be private')
        self.lock = (self.root / 'transaction.lock').open('a+b')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.lock.close()
            raise Rejected('Another transaction owns this directory')
        self.path = self.root / 'journal.json'
        try:
            self.state = json.loads(self.path.read_text()) if self.path.exists() else {
                'format': 1, 'package_sha256': package.key, 'phase': 'NEW', 'events': []}
            require(self.state['format'] == 1 and isinstance(self.state['events'], list), 'Invalid journal')
            require(self.state['package_sha256'] == package.key, 'Journal belongs to a different candidate package')
        except BaseException:
            self.close()
            raise

    def close(self):
        if not self.lock.closed:
            fcntl.flock(self.lock, fcntl.LOCK_UN)
            self.lock.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def record(self, phase, **details):
        self.state['phase'] = phase
        self.state['events'].append({'sequence': len(self.state['events']), 'phase': phase, **details})
        atomic_json(self.path, self.state)

    def identity(self, backend):
        scope = getattr(backend, 'write_scope', 'program')
        require(scope in ('program', 'pair'), 'Unknown backend write scope')
        kinds = {e['backend_kind'] for e in self.state['events'] if 'backend_kind' in e}
        scopes = {e.get('write_scope', 'program') for e in self.state['events'] if 'backend_kind' in e}
        require(not kinds or kinds == {backend.kind}, 'Journal backend kind cannot change')
        require(not scopes or scopes == {scope}, 'Journal backend write scope cannot change')
        require(backend.kind == 'offline-fixture' or
                self.package.manifest.get('hardware_adapter_available') is True,
                'No validated hardware adapter for this package')
        value = backend.identity()
        require(digest(canonical(value)) == self.package.manifest['identity_sha256'], 'Target identity mismatch')
        return self.package.manifest['identity_sha256']

    def inspect(self, backend):
        identity = self.identity(backend)
        current = {n: digest(backend.read_program(n)) for n in PROGRAMS}
        kinds = {n: ('baseline' if h == self.package.expected('baseline')[n] else
                     'candidate' if h == self.package.expected('candidate')[n] else 'unknown')
                 for n, h in current.items()}
        result = {'package_sha256': self.package.key, 'identity_sha256': identity,
                  'current_sha256': current, 'classification': kinds,
                  'backend_kind': backend.kind, 'write_scope': getattr(backend, 'write_scope', 'program')}
        result['inspection_sha256'] = digest(canonical(result))
        return result

    def install(self, backend):
        # These checks occur BEFORE identity() can connect to a device.
        self.package.require_release()
        require(self.state['phase'] == 'NEW', 'Installation has already started; inspect before recovery')
        return self._write_pair(backend, 'candidate', self.package.expected('baseline'), 'INSTALL')

    def restore(self, backend, inspection):
        # A read-only inspection is reviewable even after a partial write.
        # Require the complete freshly read pair to remain exactly unchanged.
        allowed = {'NEEDS_REVIEW', 'INSTALL_READBACK_VERIFIED', 'INSTALL_WRITE_INTENT',
                   'INSTALL_FILE_VERIFIED', 'RESTORE_WRITE_INTENT', 'RESTORE_FILE_VERIFIED',
                   'INSTALL_PAIR_WRITE_INTENT', 'RESTORE_PAIR_WRITE_INTENT',
                   'INSTALL_PAIR_RECEIPT_VERIFIED', 'RESTORE_PAIR_RECEIPT_VERIFIED'}
        require(self.state['phase'] in allowed, 'There is no started installation to restore')
        require(any(e['phase'] in ('INSTALL_WRITE_INTENT', 'INSTALL_PAIR_WRITE_INTENT') for e in self.state['events']),
                'No installation write was attempted; do not overwrite an unrelated current pair')
        require(inspection.get('package_sha256') == self.package.key, 'Wrong recovery package')
        supplied = dict(inspection)
        key = supplied.pop('inspection_sha256', None)
        require(key == digest(canonical(supplied)), 'Invalid recovery inspection')
        require(supplied['identity_sha256'] == self.package.manifest['identity_sha256'], 'Wrong recovery target')
        require(supplied['backend_kind'] == backend.kind, 'Recovery inspection uses a different backend kind')
        require(supplied.get('write_scope', 'program') == getattr(backend, 'write_scope', 'program'),
                'Recovery inspection uses a different write scope')
        return self._write_pair(backend, 'baseline', supplied['current_sha256'], 'RESTORE')

    def _native_pair(self, backend, role, expected_current, action):
        """One native invocation; no per-file fallback and no retry on ambiguity.

        The adapter must compare BOTH source hashes under its exclusive native
        session immediately before mutation. A receipt never replaces host
        readback. Internal rollback is a failed install, even if verified.
        """
        targets = self.package.expected(role)
        if targets == expected_current:
            return
        require(callable(getattr(backend, 'write_pair', None)), 'Pair backend has no write_pair method')
        # Last host-side comparison; the adapter must close the remaining race.
        current = {n: digest(backend.read_program(n)) for n in PROGRAMS}
        require(current == expected_current, 'Program pair changed before native invocation')
        intent = {'package_sha256': self.package.key, 'action': action,
                  'identity_sha256': self.package.manifest['identity_sha256'],
                  'sequence': len(self.state['events']),
                  'expected_current_sha256': dict(expected_current), 'target_sha256': targets}
        operation_id = digest(canonical(intent))
        self.record(action + '_PAIR_WRITE_INTENT', **intent, operation_id=operation_id,
                    backend_kind=backend.kind, write_scope='pair')
        receipt = backend.write_pair(
            {n: self.package.files[n][role] for n in PROGRAMS},
            expected_current_sha256=dict(expected_current), operation_id=operation_id)
        require(isinstance(receipt, dict) and receipt.get('format') == 1, 'Invalid native pair receipt')
        require(receipt.get('operation_id') == operation_id, 'Native receipt belongs to a different operation')
        outcome = receipt.get('outcome')
        require(outcome in ('written', 'rolled_back', 'rejected_before_write'), 'Unknown native pair outcome')
        require(receipt.get('before_sha256') == expected_current, 'Native source pair mismatch')
        expected_after = targets if outcome == 'written' else expected_current
        require(receipt.get('after_sha256') == expected_after, 'Native final pair mismatch')
        actual = {n: digest(backend.read_program(n)) for n in PROGRAMS}
        require(actual == expected_after, 'Native receipt disagrees with full pair readback')
        self.record(action + '_PAIR_RECEIPT_VERIFIED', operation_id=operation_id,
                    outcome=outcome, before_sha256=dict(expected_current), after_sha256=actual,
                    backend_kind=backend.kind, write_scope='pair')
        require(outcome == 'written', 'Native pair did not install target: ' + outcome)

    def _write_pair(self, backend, role, expected_current, action):
        scope = getattr(backend, 'write_scope', 'program')
        try:
            initial = self.inspect(backend)
            require(initial['current_sha256'] == expected_current, 'Current program pair changed; no writes started')
            self.record(action + '_PREFLIGHT_VERIFIED', backend_kind=backend.kind,
                        write_scope=scope, current_sha256=initial['current_sha256'])
            if scope == 'pair':
                self._native_pair(backend, role, expected_current, action)
            for name in PROGRAMS:
                raw = self.package.files[name][role]
                target = digest(raw)
                # Recheck immediately before each write. Concurrent mutation is
                # not silently overwritten. The adapter still needs a native
                # exclusive session; host locking alone is insufficient.
                if scope == 'program':
                    require(digest(backend.read_program(name)) == expected_current[name], 'Program changed before write: ' + name)
                if scope == 'program' and target != expected_current[name]:
                    self.record(action + '_WRITE_INTENT', program=name, expected_sha256=target,
                                backend_kind=backend.kind, write_scope=scope)
                    backend.write_program(name, raw)
                readback = backend.read_program(name)
                require(len(readback) == len(raw) and digest(readback) == target, 'Full readback mismatch: ' + name)
                self.record(action + '_FILE_VERIFIED', program=name, sha256=target,
                            backend_kind=backend.kind, write_scope=scope)
            final = self.inspect(backend)
            require(final['current_sha256'] == self.package.expected(role), 'Final pair verification failed')
            self.record(action + '_READBACK_VERIFIED', backend_kind=backend.kind,
                        write_scope=scope,
                        boot_verified=False, settings_verified=False, jpeg_verified=False)
            return final
        except BaseException as error:
            # Even cancellation is uncertain after a write intent. Preserve
            # evidence and stop; the next invocation cannot repeat install.
            self.record('NEEDS_REVIEW', failed_during=self.state['phase'],
                        error_type=type(error).__name__, backend_kind=backend.kind, write_scope=scope)
            raise
