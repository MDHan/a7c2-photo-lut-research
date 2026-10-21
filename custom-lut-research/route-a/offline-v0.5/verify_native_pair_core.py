"""Build and verify the C pair engine; never imports device transport."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile

HERE = Path(__file__).resolve().parent
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    evidence = HERE / 'installer-evidence'
    source_names = ('native/pair_core.h', 'native/pair_core.c', 'native/sha256.h',
                    'native_pair_report.py', 'test_native_pair_core.py', 'verify_native_pair_core.py')
    source_hashes = {name: sha(HERE / name) for name in source_names}
    command = ['clang', '-target', 'aarch64-none-elf', '-std=c11', '-O2', '-ffreestanding',
               '-fno-builtin', '-fno-stack-protector', '-fno-unwind-tables',
               '-fno-asynchronous-unwind-tables', '-Wall', '-Wextra', '-Werror',
               '-c', str(HERE / 'native/pair_core.c')]
    with tempfile.TemporaryDirectory(prefix='lut-native-aarch64-') as directory:
        obj = Path(directory) / 'pair_core.o'
        subprocess.run(command + ['-o', str(obj)], check=True, capture_output=True)
        with obj.open('rb') as stream:
            elf = ELFFile(stream)
            assert elf['e_machine'] == 'EM_AARCH64' and elf['e_type'] == 'ET_REL'
            undefined = [s.name for s in elf.get_section_by_name('.symtab').iter_symbols()
                         if s.name and s['st_shndx'] == 'SHN_UNDEF']
            assert undefined == [], undefined
            text_size = elf.get_section_by_name('.text')['sh_size']
        object_hash = sha(obj)
    result = subprocess.run([sys.executable, str(HERE / 'test_native_pair_core.py')],
                            text=True, capture_output=True, check=True)
    log = evidence / 'native-core-tests.log'
    log.write_text(result.stdout + result.stderr)
    assert 'Ran 8 tests' in log.read_text() and '\nOK\n' in log.read_text()
    assert source_hashes == {name: sha(HERE / name) for name in source_names}
    manifest = json.loads((HERE / 'dev-menu-02/manifest.json').read_text())
    report = {
        'status': 'NATIVE_CORE_OFFLINE_VERIFIED_PLATFORM_ADAPTER_MISSING',
        'camera_io': False, 'candidate_flash_ready': False,
        'sources': source_hashes, 'test_log_sha256': sha(log),
        'compiler': subprocess.run(['clang', '--version'], text=True, capture_output=True, check=True).stdout,
        'cross_compile_command': command + ['-o', '<temporary>/pair_core.o'],
        'aarch64_object': {'sha256': object_hash, 'text_bytes': text_size,
                          'undefined_symbols': undefined, 'deployable_shared_object': False},
        'host_native_tests': 8,
        'actual_candidate_copy_test': {'candidate': 'dev-menu-02',
                                       'sha256': {n: v['sha256'] for n, v in manifest['outputs'].items()},
                                       'fixed_window_install_and_restore_byte_identical': True,
                                       'inode_preserved': True},
        'verified': ['C SHA-256 over full AP/CP files, source verification before and after writable reopen',
                     'Fixed window ordering/bounds and preimage checks before mutation',
                     'Actual temporary-file pread/pwrite/fsync; bounded EINTR and short-I/O handling',
                     'Rollback flush and full-pair verification; failed rollback remains unknown',
                     'Readonly/close/session cleanup failure cannot produce success receipt',
                     'Operation-bound binary report parsing for written and rolled-back outcomes'],
        'not_verified': ['Camera platform syscall wrapper and device session',
                         'Real mount state or process/file exclusivity on camera',
                         'Deployable AArch64 shared-module loading and report transport',
                         'Settings preservation, WBI, boot, JPEG output, or inaccessible-body recovery']}
    (evidence / 'native-core-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'camera_io', 'host_native_tests', 'aarch64_object')}, indent=2))


if __name__ == '__main__':
    main()
