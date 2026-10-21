"""Execute native CP release/queue/callback paths with explicit OS/MMIO fixtures.

This is a counterexample to treating bb30ce as an asynchronous drain, not a
hardware emulator or proof that a particular callback interleaving is reachable.
No device modules are imported and no firmware files are modified.
"""
import argparse
import hashlib
import importlib.metadata
import json
import struct
from pathlib import Path

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
from unicorn import arm_const as ar
import verify as v

HERE = Path(__file__).resolve().parent
EXPECTED_CP = '48ff01e346ac74e78b61f811725c0bd95ab2712938b55ad607a5b2f54a3bf4e1'
OWNER, BUFFER, REQUEST = v.RAM + 0x100, v.RAM + 0x200, v.RAM + 0x300
MMIO = v.RAM + 0x4000
RANGES = [(0xbb30ce, 0xbb31e0), (0xbb2e22, 0xbb2e6c),
          (0x54e914, 0x54e950), (0xbb42da, 0xbb4302),
          (0xbb436a, 0xbb439e), (0xbb2074, 0xbb20d2),
          (0xb78a0e, 0xb78b0a), (0xb829c8, 0xb829d0),
          (0xb781ba, 0xb781e6), (0xb7810a, 0xb78136),
          (0xbb2fac, 0xbb2ff0), (0xbb4326, 0xbb434a),
          (0xbb20d2, 0xbb211e), (0x4e89f0, 0x4e8a40),
          (0xb79576, 0xb79632), (0xb83282, 0xb8336c)]


class Native:
    def __init__(self, cp, group=0, ready=True, lookup_error=0):
        self.u = u = v.n.cp_machine()
        u.mem_write(0x108000, cp)
        self.group, self.lookup_error = group, lookup_error
        self.events, self.accesses, self.queued = [], [], []
        # RAM-backed register banks: record instruction behavior, not hardware
        # completion, DMA cancellation, or effects of write-one registers.
        for channel in range(7):
            driver = MMIO + channel * 0x100
            control = MMIO + 0x1000 + channel * 0x200
            v.put(u, 0xe9515c + channel * 4, driver)
            v.put(u, 0xe9d550 + channel * 4, control - 0x1000)
            v.put(u, control + 0xfc, 0x1111 if ready else 0)
            v.put(u, 0xe9d588 + channel * 8, channel)
            v.put(u, 0xe9d58c + channel * 8, channel)
        v.put(u, OWNER, 0x8833)
        v.put(u, v.RES, 0x8833)
        v.put(u, v.STATE, 2)
        v.put(u, v.DESC, 9)
        v.put(u, v.TOKEN, 0x123)
        u.mem_write(v.PENDING, b'\1')
        self.saved = {v.reg(i): 0x11800000 + i for i in range(4, 12)}
        u.hook_add(UC_HOOK_CODE, self.code)
        u.hook_add(UC_HOOK_MEM_WRITE, self.memory)
        u.hook_add(UC_HOOK_MEM_READ, self.memory)

    def ret(self, value=0):
        self.u.reg_write(v.reg(0), value & 0xffffffff)
        self.u.reg_write(ar.UC_ARM_REG_PC, self.u.reg_read(ar.UC_ARM_REG_LR))

    def code(self, u, pc, size, _):
        args = [u.reg_read(v.reg(i)) for i in range(4)]
        if pc == 0x54d788:  # owner registry lookup, explicit fixture
            assert args[1] == 0x8833
            if not self.lookup_error:
                v.put(u, args[2], self.group)
            self.events.append('owner_lookup')
            self.ret(self.lookup_error)
        elif pc == 0x61ed00:  # zero-fill ABI, not resource logic
            u.mem_write(args[0], bytes(args[1]))
            self.ret()
        elif pc == 0xb7a0aa:  # diagnostic verbosity only
            self.ret(3)
        elif pc in (0xbb084e, 0xb4457a, 0xb7d358):
            self.ret()
        elif pc == 0x565204:  # OS message allocation
            assert args[0] == 0x2ae085a and args[2:] == [0x38, 0]
            v.put(u, args[1], BUFFER)
            self.events.append('os_allocate')
            self.ret()
        elif pc == 0xbec024:  # message bookkeeping boundary
            assert args[:2] == [BUFFER, 0x2ae085a]
            self.ret()
        elif pc == 0x564b38:  # OS enqueue; intentionally does not run callback
            assert args[:2] == [0x2ae085a, BUFFER]
            self.queued.append(bytes(u.mem_read(BUFFER, 0x38)))
            self.events.append('os_enqueue')
            self.ret()
        else:
            assert any(lo <= pc < hi for lo, hi in RANGES), hex(pc)

    def memory(self, u, access, address, size, value, _):
        self.accesses.append((access, address, size))

    def call(self, pc, *args):
        u = self.u
        for reg, value in self.saved.items():
            u.reg_write(reg, value)
        for i, value in enumerate(args):
            u.reg_write(v.reg(i), value)
        u.reg_write(ar.UC_ARM_REG_SP, v.SP)
        u.reg_write(ar.UC_ARM_REG_LR, v.STOP | 1)
        u.emu_start(pc | 1, v.STOP, count=30000)
        assert u.reg_read(ar.UC_ARM_REG_PC) == v.STOP
        assert u.reg_read(ar.UC_ARM_REG_SP) == v.SP
        assert all(u.reg_read(r) == x for r, x in self.saved.items())
        return u.reg_read(v.reg(0))


def verify(cp):
    cases = []
    for group in range(7):
        for pending in (0, 1):
            n = Native(cp, group)
            n.u.mem_write(v.PENDING, bytes([pending]))
            assert n.call(0xbb30ce, OWNER) == 0
            assert v.word(n.u, v.RES) == 0
            assert n.u.mem_read(v.PENDING, 1) == bytes([pending])
            assert v.word(n.u, v.STATE) == 2
            assert v.word(n.u, v.DESC) == 9
            assert not any(a <= v.PENDING < a + s for _, a, s in n.accesses)
            assert not any(x.startswith('os_') for x in n.events)
            # Real driver wrappers, register writes and reservation clearing ran.
            assert v.word(n.u, MMIO + group * 0x100 + 4) == 1
            assert v.word(n.u, MMIO + group * 0x100 + 12) == 1
            cases.append({'group': group, 'pending': pending,
                          'returned': 0, 'reservation': 0,
                          'pending_untouched': True, 'os_queue_calls': 0})
    for label, kwargs, expected in [
        ('channel_not_ready', {'ready': False}, 8),
        ('invalid_group', {'group': 8}, 8),
        ('owner_lookup_failure', {'lookup_error': 5}, 5),
    ]:
        n = Native(cp, **kwargs)
        assert n.call(0xbb30ce, OWNER) == expected
        assert v.word(n.u, v.RES) == 0x8833
        assert n.u.mem_read(v.PENDING, 1) == b'\1'
        cases.append({'case': label, 'returned': expected, 'reservation_preserved': True})

    # Execute real message construction/copy/enqueue and then real release.
    # The OS fixture retains the accepted message; hardware ordering is unknown.
    n = Native(cp)
    request = struct.pack('<6I', 1, 2, 3, 4, 5, 6)
    n.u.mem_write(REQUEST, request)
    assert n.call(0xb79576, 0, REQUEST, 0x4e89f1) == 0
    assert len(n.queued) == 1
    message = n.queued[0]
    assert struct.unpack_from('<4I', message) == (2, 0x1e, 0, 0x4e89f1)
    assert message[0x1c:0x34] == request
    n.events.clear()
    assert n.call(0xbb30ce, OWNER) == 0
    assert len(n.queued) == 1 and 'os_enqueue' not in n.events
    assert n.u.mem_read(v.PENDING, 1) == b'\1'

    late = []
    for callback_result in (0, 1):
        # Hypothetical next-generation state; not proof the scheduler permits it.
        v.put(n.u, v.STATE, 2)
        v.put(n.u, v.DESC, 0x99)
        v.put(n.u, v.TOKEN, 0x456)
        n.u.mem_write(v.PENDING, b'\1')
        n.call(0x4e89f0, callback_result)
        assert n.u.mem_read(v.PENDING, 1) == b'\0'
        assert v.word(n.u, v.STATE) == (0 if callback_result else 2)
        assert v.word(n.u, v.DESC) == (0 if callback_result else 0x99)
        assert v.word(n.u, v.TOKEN) == 0x456
        late.append({'callback_result': callback_result, 'pending_cleared': True,
                     'new_descriptor_cleared': bool(callback_result),
                     'generation_token_unchanged': True})
    return {'release_cases': cases, 'native_queue_message_verified': True,
            'late_callback_fixture': late,
            'conclusion': 'bb30ce is not a proven drain/cancel primitive; callback has no generation guard',
            'limitations': ['RAM-backed MMIO has no hardware side effects',
                           'owner registry and OS queue are explicit fixtures',
                           'late-callback ordering is injected, not established as runtime reachable',
                           'full native photo scheduler and buffer lifetime are not verified']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--folder', type=Path, default=HERE / 'dev-menu-02')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    cp = (args.folder / 'candidate/cpapp-b.bin').read_bytes()
    digest = hashlib.sha256(cp).hexdigest()
    assert digest == EXPECTED_CP
    report = {'cp_sha256': digest, 'status': 'NOT_READY_TO_FLASH',
              'test_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'unicorn_version': importlib.metadata.version('unicorn'),
              'camera_io': False, **verify(cp)}
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
