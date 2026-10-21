"""Offline native LUT ownership and inactivity control-flow audit.

No device imports or firmware edits. Register banks are RAM fixtures, OS
mutex/queue boundaries are fixtures, and LUT register-profile selection is
explicitly intercepted. This does not establish hardware quiescence.
"""
import hashlib
import importlib.metadata
import json
import struct
from pathlib import Path

from unicorn import arm_const as ar
import verify_resource_release as base

v = base.v
HERE = Path(__file__).resolve().parent
REGISTRY = 0x1a7e578
SHADOW = 0x1a7e538
USESTATE = 0x1a6af0c
CTX = v.RAM + 0x800
SOURCE = v.RAM + 0x9000
PTR = v.RAM + 0x500
OWNER = 0x8833
OTHER = 0x9944
# Native registry bitmask -> group mapping, checked below by execution.
GROUPS = {1: 0, 2: 1, 4: 2, 8: 3, 15: 4, 3: 5, 12: 6}
CALLERS = ((0x4c3178, 0x4c321a), (0x4c763a, 0x4c76d4),
           (0x4c9946, 0x4c99e0))
EXTRA = [(0x54d788, 0x54d8d8), (0xbb2bca, 0xbb2fac),
         (0xbb2016, 0xbb2074), (0xbb399a, 0xbb39aa),
         (0xbb4302, 0xbb4326), (0xbb434a, 0xbb436a),
         (0x4e876c, 0x4e8970), (0xb31a54, 0xb31aac),
         (0x54e15c, 0x54e380), (0x54e398, 0x54e658),
         (0xb799de, 0xb79b86), (0xb7800e, 0xb7810a),
         (0xb78136, 0xb781ba), (0xb78794, 0xb78812),
         (0xb78990, 0xb78a0e), (0xb78b0a, 0xb78b88),
         (0xb82948, 0xb829d4), (0x4e7edc, 0x4e7f9a)]
CONFIG_FIXTURES = {0xb78fda, 0xb7905e, 0xb790e2, 0xb793f0,
                   0xb794f4, 0xb79472, 0xb78c60}


class Ownership(base.Native):
    def __init__(self, cp, mask=15, mode=0, ready=True, enabled=True):
        super().__init__(cp, ready=ready)
        self.timeline = []
        self.allocations = 0
        self.prefix = False
        self.caller_range = None
        self.release_calls = 0
        self.set_registry(mask, mode)
        for i in range(4):
            v.put(self.u, SHADOW + i * 4, (1 << 21) if enabled else 0)
        # Valid address-conversion input, not actual mapped LUT bytes or DMA.
        self.u.mem_write(0xceedb0, struct.pack('<QQQQ', 0x7000000, 0x7000000,
                                            0x7100000, 0x100000))
        self.u.mem_write(CTX, bytes(120))
        for offset, value in [(0, 9), (8, 10), (0x18, 0x7000000),
                              (0x20, 0x7008000), (0x28, 0xbb80), (0x70, 0x123)]:
            v.put(self.u, CTX + offset, value)

    def set_registry(self, mask, mode, owner=OWNER):
        for i in range(4):
            self.u.mem_write(REGISTRY + i * 8, struct.pack('<II',
                owner if mask & (1 << i) else OTHER, mode + 1))

    def code(self, u, pc, size, unused):
        args = [u.reg_read(v.reg(i)) for i in range(4)]
        if self.prefix and pc == 0x4e7f9a:
            u.emu_stop()
            return
        if pc == 0x4e7edc:
            p = v.word(u, u.reg_read(ar.UC_ARM_REG_SP) + 0x10)
            self.prefix_flags = tuple(struct.unpack('<4I', u.mem_read(p, 16)))
            self.prefix_pointer = p
            assert args[0] == OWNER
        if pc == 0xbb30ce:
            self.release_calls += 1
        if pc == 0x5f267c:
            self.ret(0)  # normal task context, not ISR
            return
        if pc in (0x5ee450, 0x5ee8a8):
            assert args[0] == 0x4f
            self.timeline.append('registry_lock' if pc == 0x5ee450 else 'registry_unlock')
            self.ret(0)
            return
        if pc == 0xbb084a:
            self.ret(0)
            return
        if pc in CONFIG_FIXTURES:
            # Lower-level profile/register programming is out of this audit.
            self.timeline.append({'config_fixture': hex(pc), 'channel': args[0]})
            self.ret(0)
            return
        if pc == 0x565204:
            assert args[0] == 0x2ae085a and args[2:] == [0x38, 0]
            v.put(u, args[1], v.RAM + 0x6000 + self.allocations * 0x80)
            self.allocations += 1
            self.ret(0)
            return
        if pc == 0xbec024:
            assert args[1] == 0x2ae085a
            self.ret(0)
            return
        if pc == 0x564b38:
            assert args[0] == 0x2ae085a
            message = bytes(u.mem_read(args[1], 0x38))
            self.queued.append(message)
            self.timeline.append({'enqueue_type': struct.unpack_from('<I', message)[0],
                                  'reservation': v.word(u, v.RES),
                                  'pending': bytes(u.mem_read(v.PENDING, 1))[0]})
            self.ret(0)
            return
        if any(a <= pc < b for a, b in EXTRA):
            return
        if self.caller_range and self.caller_range[0] <= pc < self.caller_range[1]:
            return
        super().code(u, pc, size, unused)

    def apply(self, art=False):
        v.put(self.u, CTX + 0x2c, 0x7c if art else 0)
        self.call(0x4e876c, OWNER, CTX)

    def idle_prefix(self, caller, flags):
        # Execute the actual parameter-copying caller and native callee prefix,
        # stopping before downstream VFX construction (no false full-call claim).
        u = self.u
        self.prefix = True
        self.caller_range = CALLERS[caller]
        u.mem_write(SOURCE, bytes(0x1400))
        v.put(u, SOURCE + 0x1c0, 1)
        v.put(u, SOURCE + 0x13b4, OWNER)
        for i, flag in enumerate(flags):
            u.mem_write(SOURCE + 0x1c4 + i * 0x70, bytes([flag]))
        u.reg_write(ar.UC_ARM_REG_SP, v.SP)
        u.reg_write(v.reg(4), SOURCE)
        u.reg_write(v.reg(5), PTR)
        u.reg_write(v.reg(6), SOURCE + 0x13b4)
        u.reg_write(v.reg(11), 0)
        v.put(u, PTR, 0)
        u.emu_start(self.caller_range[0] | 1, v.STOP, count=30000)
        assert u.reg_read(ar.UC_ARM_REG_PC) == 0x4e7f9a
        assert self.prefix_flags == tuple(flags)
        self.prefix = False
        return tuple(struct.unpack('<4I', u.mem_read(self.prefix_pointer, 16)))


def verify(cp):
    registry = []
    for mode in (0, 1):
        for mask in range(16):
            n = Ownership(cp, mask, mode)
            v.put(n.u, PTR, 0xa5a5a5a5)
            result = n.call(0x54d788, mode, OWNER, PTR)
            assert result == (0 if mask in GROUPS else 5)
            assert v.word(n.u, PTR) == GROUPS.get(mask, 0xa5a5a5a5)
            assert n.timeline == ['registry_lock', 'registry_unlock']
            registry.append({'mode': mode, 'mask': mask, 'result': result,
                             'group': GROUPS.get(mask)})

    loads = []
    for mask, group in GROUPS.items():
        for mode in (0, 1):
            for art in (False, True):
                n = Ownership(cp, mask, mode, enabled=False)
                v.put(n.u, v.STATE, 0)
                v.put(n.u, v.DESC, 0)
                v.put(n.u, v.RES, 0)
                n.u.mem_write(v.PENDING, b'\0')
                n.apply(art)
                assert v.word(n.u, v.STATE) == 1
                assert v.word(n.u, v.RES) == OWNER
                assert not n.queued
                n.apply(art)
                assert v.word(n.u, v.STATE) == 2
                assert v.word(n.u, v.RES) == 0
                assert n.u.mem_read(v.PENDING, 1) == b'\1'
                assert v.word(n.u, v.DESC) == 9
                assert v.word(n.u, v.TOKEN) == 0x123
                types = [struct.unpack_from('<I', m)[0] for m in n.queued]
                assert types == ([1, 3, 2] if art else [1, 2])
                assert all(struct.unpack_from('<I', m, 8)[0] == group for m in n.queued)
                assert all(row['reservation'] == OWNER and row['pending'] == 1
                           for row in n.timeline if isinstance(row, dict) and 'enqueue_type' in row)
                assert n.call(0xb31a54, 9, 10, CTX + 0x18) == 0
                n.call(0x4e89f0, 0)
                assert n.call(0xb31a54, 9, 10, CTX + 0x18) == 1
                loads.append({'mask': mask, 'group': group, 'mode': mode, 'art': art,
                              'queued_types': types, 'reservation_zero_before_callback': True})

    # A prior reservation value is not an exclusion check in bb2bca.
    overwrite = []
    for enabled in (False, True):
        n = Ownership(cp, enabled=enabled)
        v.put(n.u, v.RES, OTHER)
        assert n.call(0xbb2bca, base.OWNER) == 0
        assert v.word(n.u, v.RES) == OWNER
        overwrite.append({'enabled_shadow': enabled, 'old_owner': OTHER, 'new_owner': OWNER})

    inactivity = []
    for caller in range(3):
        n = Ownership(cp)
        n.u.mem_write(v.PENDING, b'\0')
        v.put(n.u, USESTATE, 0)
        for expected, calls in [(1, 0), (2, 1), (2, 1)]:
            assert n.idle_prefix(caller, [0, 0, 0, 0]) == (0, 0, 0, 0)
            assert v.word(n.u, USESTATE) == expected and n.release_calls == calls
        for i in range(4):
            flags = [0, 0, 0, 0]
            flags[i] = 1
            v.put(n.u, USESTATE, 2)
            assert n.idle_prefix(caller, flags) == tuple(flags)
            assert v.word(n.u, USESTATE) == 0 and n.release_calls == 1
        for state, pending in [(0, 0), (1, 0), (2, 1)]:
            v.put(n.u, v.STATE, state)
            n.u.mem_write(v.PENDING, bytes([pending]))
            v.put(n.u, USESTATE, 1)
            assert n.idle_prefix(caller, [1, 1, 1, 1]) == (0, 0, 0, 0)
            assert v.word(n.u, USESTATE) == 1 and n.release_calls == 1
        # Native release returns 8 when the RAM-backed status is not ready.
        # The caller still advances to 2 and does not retry on the next zero input.
        n = Ownership(cp, ready=False)
        n.u.mem_write(v.PENDING, b'\0')
        v.put(n.u, USESTATE, 1)
        assert n.idle_prefix(caller, [0] * 4) == (0, 0, 0, 0)
        assert n.release_calls == 1 and v.word(n.u, USESTATE) == 2
        assert v.word(n.u, v.RES) == OWNER
        n.idle_prefix(caller, [0] * 4)
        assert n.release_calls == 1
        inactivity.append({'caller': hex(CALLERS[caller][0]), 'cases': 12,
                           'parameter_offsets': ['0x1c4', '0x234', '0x2a4', '0x314'],
                           'failed_release_advances_state_without_retry': True})
    return {'registry_cases': registry, 'load_cases': loads,
            'reservation_overwrite_cases': overwrite, 'inactivity_cases': inactivity,
            'limitations': [
                'RAM-backed MMIO; no hardware completion, cache, or DMA side effects',
                'OS registry locks, allocation and enqueue are explicit fixtures',
                'seven lower-level LUT profile/configuration functions are explicit success fixtures',
                'registry contents and address conversion table are supplied test data',
                'inactivity cases execute caller setup and callee prefix only',
                'no assertion that injected acquisition ordering is reachable in the full scheduler',
                'no proof of LUT data persistence, last-reader fence, cancellation or safe reuse']}


def main():
    cp = (HERE / 'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    assert hashlib.sha256(cp).hexdigest() == base.EXPECTED_CP
    result = verify(cp)
    result['cp_sha256'] = base.EXPECTED_CP
    result['unicorn_version'] = importlib.metadata.version('unicorn')
    result['source_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in [Path(__file__), Path(base.__file__), Path(v.__file__)]}
    out = HERE / 'lifecycle-dev/ownership-verification.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'report': str(out), 'registry': len(result['registry_cases']),
                      'loads': len(result['load_cases']), 'inactivity': 36,
                      'reservation_overwrites': len(result['reservation_overwrite_cases'])}))


if __name__ == '__main__':
    main()
