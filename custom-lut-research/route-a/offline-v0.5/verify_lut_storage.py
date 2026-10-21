"""Execute native boot mapping, BSS clear/publication and stored callbacks."""
import hashlib
import json
from pathlib import Path
import struct
from unicorn import UC_HOOK_CODE
from unicorn import arm_const as ar

import build_lifecycle_storage as storage
import verify_lut_lifetime as life

v = life.v
HERE = Path(__file__).resolve().parent
START, END = storage.BSS_START, storage.STATE_BASE
FLAG = 0x108d94


def machine(cp):
    u = v.n.cp_machine()
    u.mem_write(0x108000, cp)
    u.reg_write(ar.UC_ARM_REG_CPSR, 0x13)
    u.reg_write(ar.UC_ARM_REG_SP, v.SP)
    return u


def tables(cp, text_at_d0220000):
    u = machine(cp)
    # Only two startup mode/status bytes are hardware fixtures. The full
    # original page-table constructor and section-argument setup execute.
    u.mem_map(0x3e42000, 0x1000)
    u.mem_write(0x3e42000, bytes([int(text_at_d0220000), 0]))
    u.emu_start(0x108398, 0x108728, count=3000000)
    assert u.reg_read(ar.UC_ARM_REG_PC) == 0x108728
    l1, l2, count = [v.word(u, x) for x in (0x108f1c, 0x108d98, 0x108d9c)]
    assert (l1, l2) == (0x1b88000, 0x1b8c000)
    def pte(va):
        pde = v.word(u, l1 + (va >> 20)*4)
        assert pde & 3 == 1
        return v.word(u, (pde & ~1023) + ((va >> 12) & 255)*4)
    values = [pte(x) for x in storage.CELLS]
    old_data = pte(START)
    assert all(x & 0xfff == old_data & 0xfff for x in values)
    assert all(x & 0xfffff000 == END & 0xfffff000 for x in values)
    return u, bytes(u.mem_read(l1, 0xc000)), {
        'text_at_d0220000': text_at_d0220000,
        'l1': hex(l1), 'l2': hex(l2), 'l2_tables': count,
        'cell_pte': [hex(x) for x in values], 'native_boot_data_pte': hex(old_data),
        'cell_attributes_equal_native_writable_state': True}


def native_memory_ranges(u):
    calls = []
    controller = v.RAM+0x2000
    def boundary(u, pc, size, unused):
        a = [u.reg_read(v.reg(i)) for i in range(4)]
        assert a[0] == controller
        calls.append(a[1:])
        u.reg_write(v.reg(0), 0)
        u.reg_write(ar.UC_ARM_REG_PC, u.reg_read(ar.UC_ARM_REG_LR))
    h = u.hook_add(UC_HOOK_CODE, boundary, begin=0x61a1f4, end=0x61a1f4)
    u.reg_write(ar.UC_ARM_REG_CPSR, 0x13)
    u.reg_write(ar.UC_ARM_REG_SP, v.SP)
    u.reg_write(ar.UC_ARM_REG_LR, v.STOP)
    u.reg_write(v.reg(0), controller)
    u.emu_start(0x619f54, v.STOP, count=30000)
    assert u.reg_read(ar.UC_ARM_REG_PC) == v.STOP
    u.hook_del(h)
    assert all(not (a < END+8 and END < a+length) for a, length, _ in calls)
    assert [0x1b86000, 0x2000, 0] in calls
    return calls


def cold_init(u, modified):
    end = END+8 if modified else END
    # Poison the complete BSS plus guard bytes to catch missing/overlong clear.
    u.mem_write(START, bytes([0xa5])*(END+40-START))
    v.put(u, START+0x14, FLAG)
    v.put(u, FLAG, 0)
    prefix = bytes(u.mem_read(START, 0x418))
    timeline = []
    def publish(u, pc, size, unused):
        if pc == 0x60d368:
            if modified:
                assert [v.word(u, c) for c in storage.CELLS] == [0x80, 0x80]
            timeline.append('native_publish_after_initialization')
    h = u.hook_add(UC_HOOK_CODE, publish, begin=0x60d368, end=0x60d368)
    u.reg_write(ar.UC_ARM_REG_CPSR, 0x13)
    u.reg_write(ar.UC_ARM_REG_SP, v.SP)
    u.emu_start(0x60d334, 0x60d374, count=4000000)
    assert u.reg_read(ar.UC_ARM_REG_PC) == 0x60d374
    u.hook_del(h)
    assert bytes(u.mem_read(START, 0x418)) == prefix
    assert bytes(u.mem_read(START+0x418, END-START-0x418)) == bytes(END-START-0x418)
    assert bytes(u.mem_read(end, 32)) == bytes([0xa5])*32
    if modified:
        assert [v.word(u, c) for c in storage.CELLS] == [0x80, 0x80]
    else:
        assert bytes(u.mem_read(END, 8)) == bytes([0xa5])*8
    assert v.word(u, FLAG) == 1
    assert timeline == ['native_publish_after_initialization']
    return {'clear_start': hex(START+0x418), 'clear_end': hex(end),
            'boot_metadata_preserved': True, 'tail_guard_preserved': True,
            'publication_after_initialization': True}


class Stored(life.Integrated):
    def __init__(self, cp, parts):
        self.booting = False
        super().__init__(cp, parts)

    def code(self, u, pc, size, unused):
        if self.booting:
            assert (0x60d334 <= pc < 0x60d374 or
                    0x61ed00 <= pc < 0x61ee38 or
                    storage.INIT <= pc < storage.INIT+28), hex(pc)
            return
        super().code(u, pc, size, unused)


def main():
    cp = (HERE/'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    changed, code, recipe = storage.make(cp)
    mappings = []
    for mode in (False, True):
        old, old_bytes, old_result = tables(cp, mode)
        new, new_bytes, new_result = tables(changed, mode)
        assert old_bytes == new_bytes
        old_ranges = native_memory_ranges(old)
        new_ranges = native_memory_ranges(new)
        assert old_ranges == new_ranges
        mappings.append({**new_result, 'page_tables_byte_identical': True,
                         'native_memory_management_requests_identical': True,
                         'management_request_count': len(new_ranges),
                         'management_requests': new_ranges})
    initializations = [cold_init(machine(cp), False), cold_init(machine(changed), True)]

    # Execute initialization and actual tagged callbacks against the declared
    # BSS cells in one emulator, without copying or pre-initializing the cells.
    parts = life.compile_parts(storage.CELLS)
    n = Stored(changed, parts)
    n.booting = True
    initializations.append(cold_init(n.u, True))
    n.booting = False
    contexts = []
    for index, cell in enumerate(storage.CELLS):
        tag = n.core('pll_begin', cell, 15)
        assert tag == 0x102
        n.core('pll_load_complete', cell, tag, 1)
        n.core('pll_submit_complete', cell, tag, 1)
        for ch in range(4):
            n.tagged_register(ch, index, tag)
            n.configure_gate(ch, 15)
            n.call(0xbb34d4, ch)
        assert n.core('pll_take_release', cell, tag) == 1
        assert n.core('pll_release_complete', cell, tag, 1) == 1
        assert v.word(n.u, cell) == 0x180
        contexts.append({'context': index, 'cell': hex(cell), 'epoch': 1,
                         'native_callback_uses_boot_initialized_storage': True})
    # Reversible recipe: every change restores precisely the frozen source.
    undo = bytearray(changed)
    for p in recipe['patches']:
        off = p['offset']; after = bytes.fromhex(p['after'])
        assert undo[off:off+len(after)] == after
        undo[off:off+len(after)] = bytes.fromhex(p['before'])
    assert bytes(undo) == cp
    report = {'status': 'STORAGE_COMPONENT_OFFLINE_VERIFIED_NOT_READY_TO_FLASH',
              'camera_io': False, 'base_cp_sha256': storage.CP_HASH,
              'recipe': recipe, 'mapping_cases': mappings,
              'initialization_cases': initializations, 'integrated_contexts': contexts,
              'inverse_exact': True, 'full_image_written': False,
              'test_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'dependencies': {name: hashlib.sha256((HERE/name).read_bytes()).hexdigest()
                               for name in ('build_lifecycle_storage.py', 'photo_lut_storage.S',
                                            'verify_lut_lifetime.py', 'photo_lut_lifetime.c',
                                            'photo_lut_lifetime.h', 'lifecycle-dev/callback_fixture.S')},
              'limitations': ['boot hardware mode/status bytes are fixtures',
                              'memory-manager range calls captured, not full runtime allocator',
                              'no WBI resume, camera boot or hot installation validated',
                              'load/submit/release completion inputs still harness calls',
                              'no global reader drain or production installer integration']}
    (storage.OUT/'storage-verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'mapping_cases': len(mappings), 'initializations': len(initializations),
                      'stored_native_callback_contexts': len(contexts), 'status': report['status']}))


if __name__ == '__main__': main()
