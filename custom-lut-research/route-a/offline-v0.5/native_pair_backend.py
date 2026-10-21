"""Manifest-bounded host/native bridge. Session transport is injected, never discovered.

The session must implement identity(), read_program(name), and
run_native(bundle)->208-byte native report. No camera session is implemented here.
"""
from dataclasses import dataclass
import json

from install_transaction import PROGRAMS, canonical, digest, require
from native_pair_report import decode_receipt
from native_write_order import install_order


def hex_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(x in '0123456789abcdef' for x in value)


def array(raw):
    return '{' + ','.join('0x%02x' % x for x in raw) + '}'


@dataclass(frozen=True)
class NativeBundle:
    operation_id: str
    header: bytes
    metadata: bytes

    @property
    def sha256(self):
        # Length-delimit both fields; no concatenation ambiguity.
        return digest(len(self.header).to_bytes(8, 'little') + self.header + self.metadata)


class FixedWindows:
    def __init__(self, package, manifest_bytes):
        self.package = package
        require(digest(manifest_bytes) == package.manifest['firmware_manifest_sha256'],
                'Native window manifest is not bound to this package')
        manifest = json.loads(manifest_bytes)
        require(manifest['inputs'] == package.expected('baseline'), 'Native baseline pair mismatch')
        require({n: manifest['outputs'][n]['sha256'] for n in PROGRAMS} == package.expected('candidate'),
                'Native candidate pair mismatch')
        self.windows = []
        undo = {n: bytearray(package.files[n]['candidate']) for n in PROGRAMS}
        for name in PROGRAMS:
            require(len(package.files[name]['baseline']) == len(undo[name]), 'Native in-place install cannot resize files')
            require(len(undo[name]) == manifest['outputs'][name]['size'], 'Native manifest file size mismatch')
        for patch in manifest['patches']:
            name, offset, size = patch['file'], patch['offset'], patch['length']
            require(name in PROGRAMS and type(offset) is int and type(size) is int and
                    0 <= offset and 0 < size <= 4096 and offset + size <= len(undo[name]),
                    'Invalid native patch window')
            before, after = bytes.fromhex(patch['before']), bytes.fromhex(patch['after'])
            require(len(before) == size and len(after) == size, 'Native patch length mismatch')
            require(package.files[name]['baseline'][offset:offset+size] == before and
                    package.files[name]['candidate'][offset:offset+size] == after,
                    'Native patch bytes mismatch')
            self.windows.append((PROGRAMS.index(name), offset, size))
            undo[name][offset:offset+size] = before
        self.windows.sort()
        require(0 < len(self.windows) <= 4096, 'Invalid native window count')
        for previous, current in zip(self.windows, self.windows[1:]):
            require(previous[0] != current[0] or previous[1] + previous[2] <= current[1],
                    'Overlapping native patch windows')
        require(all(bytes(undo[n]) == package.files[n]['baseline'] for n in PROGRAMS),
                'Undeclared native candidate changes')
        self.install_order, self.dependencies = install_order(package, self.windows)

    def prepare(self, current, target, expected_current_sha256, operation_id):
        require(hex_digest(operation_id), 'Invalid native operation ID')
        require(set(current) == set(target) == set(expected_current_sha256) == set(PROGRAMS),
                'Native operation requires the complete pair')
        current = {n: bytes(current[n]) for n in PROGRAMS}
        target = {n: bytes(target[n]) for n in PROGRAMS}
        current_hashes = {n: digest(current[n]) for n in PROGRAMS}
        target_hashes = {n: digest(target[n]) for n in PROGRAMS}
        require(current_hashes == expected_current_sha256, 'Pair changed while preparing native operation')
        require(target_hashes in (self.package.expected('baseline'), self.package.expected('candidate')),
                'Native target is not an approved complete pair')
        # A partial previous write is recoverable only inside the approved
        # windows. Never turn unrelated corruption into permission to overwrite.
        sanitized = {n: bytearray(current[n]) for n in PROGRAMS}
        for n in PROGRAMS:
            require(len(current[n]) == len(self.package.files[n]['baseline']), 'Native source size changed')
        for file, at, size in self.windows:
            n = PROGRAMS[file]
            sanitized[n][at:at+size] = self.package.files[n]['baseline'][at:at+size]
        require(all(bytes(sanitized[n]) == self.package.files[n]['baseline'] for n in PROGRAMS),
                'Source differs outside approved native windows; recovery not authorized by this manifest')
        lines = ['/* Generated private, operation-bound AP/CP plan. */', '#include "pair_core.h"']
        rows = []
        restoring = target_hashes == self.package.expected('baseline')
        write_order = list(reversed(self.install_order)) if restoring else self.install_order
        for i, (file, at, size) in enumerate(write_order):
            n = PROGRAMS[file]
            lines += [f'static const lp_u8 before_{i}[]={array(current[n][at:at+size])};',
                      f'static const lp_u8 after_{i}[]={array(target[n][at:at+size])};']
            rows.append(f'{{{at}ULL,{file}U,{size}U,before_{i},after_{i}}}')
        lines += ['static const struct lp_window operation_windows[]={' + ','.join(rows) + '};',
                  'static const struct lp_plan operation_plan={',
                  '.size={' + ','.join(str(len(current[n])) + 'ULL' for n in PROGRAMS) + '},',
                  '.before_hash={' + ','.join(array(bytes.fromhex(current_hashes[n])) for n in PROGRAMS) + '},',
                  '.after_hash={' + ','.join(array(bytes.fromhex(target_hashes[n])) for n in PROGRAMS) + '},',
                  '.operation_id=' + array(bytes.fromhex(operation_id)) + ',',
                  '.windows=operation_windows,.count=' + str(len(rows)) + 'U};']
        header = ('\n'.join(lines) + '\n').encode()
        metadata = canonical({'format': 1, 'package_sha256': self.package.key,
                              'firmware_manifest_sha256': self.package.manifest['firmware_manifest_sha256'],
                              'operation_id': operation_id, 'header_sha256': digest(header),
                              'before_sha256': current_hashes, 'after_sha256': target_hashes,
                              'windows': write_order, 'install_dependencies': self.dependencies,
                              'restoring': restoring, 'live_patch_safety_verified': False})
        return NativeBundle(operation_id, header, metadata)


class NativePairBackend:
    write_scope = 'pair'

    def __init__(self, package, manifest_bytes, session):
        self.package, self.session = package, session
        self.kind = session.kind
        self.fixed = FixedWindows(package, manifest_bytes)

    def gate(self):
        require(self.session.kind == self.kind, 'Native session backend kind changed')
        require(self.kind == 'offline-fixture' or self.package.manifest.get('hardware_adapter_available') is True,
                'No validated hardware session for native pair backend')

    def identity(self):
        self.gate()
        return self.session.identity()

    def read_program(self, name):
        self.gate()
        require(name in PROGRAMS, 'Native backend file is not approved')
        return self.session.read_program(name)

    def write_pair(self, programs, *, expected_current_sha256, operation_id):
        self.gate()
        require(digest(canonical(self.identity())) == self.package.manifest['identity_sha256'],
                'Native session target identity changed')
        current = {n: self.read_program(n) for n in PROGRAMS}
        bundle = self.fixed.prepare(current, programs, expected_current_sha256, operation_id)
        # Exactly one invocation. Exceptions, missing reports, unknown outcomes
        # and rollback are never converted into a silent retry or second worker.
        raw = self.session.run_native(bundle)
        return decode_receipt(raw, operation_id, expected_current_sha256,
                              {n: digest(programs[n]) for n in PROGRAMS})
