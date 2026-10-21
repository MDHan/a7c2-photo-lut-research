"""Check native inactivity retry, exact composition, boot and photo regressions."""
import hashlib
import itertools
import json
from pathlib import Path

import build_release_retry as build
import verify_lut_ownership as owner
import verify_lut_storage as boot
import verify_tracked_entry as photo

v = owner.v
HERE = Path(__file__).resolve().parent


class Retry(owner.Ownership):
    def __init__(self, cp, start, size, **kwargs):
        self.handler = (start, start+size)
        self.release_results = []
        super().__init__(cp, **kwargs)

    def code(self, u, pc, size, unused):
        if pc == 0x4e7f50:
            self.release_results.append(u.reg_read(v.reg(0)))
        if self.handler[0] <= pc < self.handler[1]:
            return
        super().code(u, pc, size, unused)


def main():
    cp, layout, recipe = build.make()
    previous, _ = build.tracked.make()
    frozen = (HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    cases = 0
    for caller, mask, state, ready in itertools.product(range(3), range(16), range(3), (False, True)):
        flags = [int(bool(mask & (1 << i))) for i in range(4)]
        snapshots = []
        for raw, patched in ((previous, False), (cp, True)):
            n = Retry(raw, recipe['address'], recipe['size'], ready=ready)
            n.u.mem_write(v.PENDING, b'\0')
            v.put(n.u, owner.USESTATE, state)
            assert n.idle_prefix(caller, flags) == tuple(flags)
            snapshot = (v.word(n.u, owner.USESTATE), v.word(n.u, v.RES), n.release_calls)
            snapshots.append(snapshot)
            if mask == 0 and state == 1:
                assert n.release_results == [0 if ready else 8]
                assert snapshot == (2 if ready or not patched else 1, 0 if ready else owner.OWNER, 1)
            else:
                assert not n.release_results
        if not (mask == 0 and state == 1 and not ready):
            assert snapshots[0] == snapshots[1]
        cases += 1

    recovery = []
    for caller, failure in itertools.product(range(3), ('hardware_status', 'registry_lookup')):
        n = Retry(cp, recipe['address'], recipe['size'], ready=failure != 'hardware_status')
        if failure == 'registry_lookup':
            n.set_registry(15, 0, owner.OTHER)
        n.u.mem_write(v.PENDING, b'\0')
        v.put(n.u, owner.USESTATE, 1)
        for attempt in range(2):
            n.idle_prefix(caller, [0]*4)
            assert n.release_calls == attempt+1
            assert v.word(n.u, owner.USESTATE) == 1
            assert v.word(n.u, v.RES) == owner.OWNER
        error = 8 if failure == 'hardware_status' else 5
        assert n.release_results == [error, error]
        n.set_registry(15, 0)
        for channel in range(7):
            v.put(n.u, owner.base.MMIO + 0x1000 + channel*0x200 + 0xfc, 0x1111)
        n.idle_prefix(caller, [0]*4)
        assert n.release_results == [error, error, 0]
        assert n.release_calls == 3 and v.word(n.u, owner.USESTATE) == 2
        assert v.word(n.u, v.RES) == 0
        n.idle_prefix(caller, [0]*4)
        assert n.release_calls == 3
        recovery.append({'caller': caller, 'failure': failure, 'results': n.release_results,
                         'succeeded_on_third_attempt': True})

    # Full native boot mapping and memory-management requests are still equal.
    mappings = []
    for mode in (0, 1):
        old_machine, old_tables, _ = boot.tables(frozen, mode)
        new_machine, new_tables, mapping = boot.tables(cp, mode)
        assert old_tables == new_tables
        assert boot.native_memory_ranges(old_machine) == boot.native_memory_ranges(new_machine)
        mappings.append({**mapping, 'mode': mode, 'tables_and_memory_requests_equal': True})

    # Existing entry/core/tag/callback bytes are unchanged. Check their integration
    # with the new declared text extent using cold init and both photo contexts.
    smoke = []
    for context, mode in itertools.product((0, 1), ('ready', 'async_load')):
        n = photo.Photo(cp, layout, context=context, mode=mode)
        assert n.run() == (0x48c790, 0)
        n.finish_vfx()
        assert v.word(n.u, n.cell) == 0x100
        n.descriptor_check(True)
        smoke.append({'context': context, 'mode': mode, 'completed_photo_state': '0x100'})

    # Rebuilds and inverse checks must remain tied to the exact checked binary.
    again, _, recipe2 = build.make()
    assert again == cp and recipe2 == recipe
    report = {'status': 'RELEASE_RETRY_OFFLINE_VERIFIED_NOT_READY_TO_FLASH',
              'camera_io': False, 'in_memory_cp_sha256': recipe['in_memory_cp_sha256'],
              'comparison_cases': cases, 'recovery_cases': recovery,
              'boot_mapping_cases': mappings, 'photo_smoke_cases': smoke,
              'repeat_build_identical': True, 'recipe': recipe,
              'sources': {name: hashlib.sha256((HERE/name).read_bytes()).hexdigest()
                          for name in ('verify_release_retry.py', 'verify_lut_ownership.py',
                                       'verify_resource_release.py', 'verify_tracked_entry.py',
                                       'verify_lut_storage.py')},
              'limitations': ['RAM hardware status and OS fixtures inherited from ownership audit',
                              'inactivity prefix and photo paths checked separately',
                              'no global reader exclusion or DMA cancellation added',
                              'completed photo cells still held; continuous capture not enabled',
                              'no installation package, WBI verification or camera execution']}
    (build.OUT/'verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'comparison_cases': cases, 'recoveries': len(recovery),
                      'photo_cases': len(smoke), 'status': report['status']}))


if __name__ == '__main__':
    main()
