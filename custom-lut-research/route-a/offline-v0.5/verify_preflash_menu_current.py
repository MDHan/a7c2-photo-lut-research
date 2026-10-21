"""Recheck setting/queue fixtures against the frozen dev-menu-03 image.

Earlier setting reports target dev-menu-02. This explicitly runs their native
instruction harnesses on dev-menu-03 without modifying either candidate.
No device transport is imported or invoked by these harnesses.
"""
import hashlib
import json
from pathlib import Path

from verify_pp_setting_banks import Banks
from verify_pp_exclusion_queue import Drain
from verify_settings_commit import Commit

HERE = Path(__file__).resolve().parent
OUT = HERE / 'preflash-review-20261019'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    folder = HERE / 'dev-menu-03'
    readiness = json.loads((folder / 'readiness.json').read_text())
    pair = {name: sha((folder / 'candidate' / name).read_bytes())
            for name in readiness['candidate_sha256']}
    assert pair == readiness['candidate_sha256']
    raw = (folder / 'candidate/appFw.so').read_bytes()
    banks = [Banks(raw).exercise(pp, split, general, shooting)
             for pp in range(12, 16) for split in (0, 1)
             for general, shooting in ((0, 0), (1, 1), (0, 1), (1, 0))]
    queue = []
    for pp in range(12, 16):
        for exposure in range(0x172c, 0x1730):
            row = Drain(raw).choose_and_drain(pp, exposure)
            assert row['active_profile_after_queue'] == pp
            queue.append({'case': 'PASM', **row})
        row = Drain(raw).choose_and_drain(pp, 0x172c, extra_constraint=True)
        assert row['active_profile_after_queue'] == 0
        queue.append({'case': 'independent_constraint_retained', **row})
        row = Drain(raw).choose_and_drain(pp, 0x172c, restore_bank=True)
        assert row['active_profile_after_queue'] == pp
        queue.append({'case': 'photo_bank_restore_helper', **row})
    commits = []
    for pp in range(12, 16):
        for cached in ((0, 2), (pp, 2), (0, 7), (pp, 7)):
            native = Commit(raw)
            messages = native.commit((pp, 7), cached)
            native.consume()
            expected = [{'subsystem': 0x2cf, 'key': r[3], 'bytes': bytes([v]).hex()}
                        for r, v, old in zip(native.records, (pp, 7), cached) if v != old]
            assert native.backup_calls == expected
            reader = Commit(raw)
            reader.storage = dict(native.storage)
            reader.load_cache()
            commits.append({'profile': pp, 'cached': cached, 'messages': messages,
                            'writes': native.backup_calls, 'reads': reader.backup_reads})
    report = {
        'status': 'OFFLINE_MENU_SUBPATHS_PASS_NOT_FLASH_READY', 'camera_io': False,
        'candidate_sha256': pair, 'banks': banks, 'queue': queue, 'commits': commits,
        'source_sha256': {name: sha((HERE / name).read_bytes()) for name in (
            Path(__file__).name, 'verify_pp_setting_banks.py', 'verify_pp_exclusion_queue.py',
            'verify_settings_commit.py', 'verify_menu.py', 'verify_dynamic_menu.py', 'build.py')},
        'limitations': [
            'Backup service, locks, runtime containers and secondary notifications are fixtures.',
            'Queue tests supply partial parameter states and empty observer lists.',
            'Restore helper is executed; the complete mode-switch driver is not.',
            'Import, rename/delete, full UI dispatch, MR and cold-boot persistence remain unverified.',
            'No CP hardware processing, JPEG output or camera installer acceptance.'],
    }
    assert pair == {n: sha((folder / 'candidate' / n).read_bytes()) for n in pair}
    OUT.mkdir(exist_ok=True)
    (OUT / 'current-menu-settings.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'banks': len(banks),
                      'queue': len(queue), 'commits': len(commits)}), flush=True)


if __name__ == '__main__':
    main()
