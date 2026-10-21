"""Native photo VFX callback slots, completion dispatch and wait, offline only.

OS scheduling and device status are injected. This proves local instruction
behavior, not reachability of arbitrary device completion orders or a DMA fence.
"""
import hashlib
import itertools
import json
from pathlib import Path
import struct

import verify_resource_release as release
from unicorn import arm_const as ar, UC_HOOK_CODE

v = release.v
HERE = Path(__file__).resolve().parent
SLOTS = 0x1a7e598
QUEUES = 0x11d1f94
PARAMS = v.RAM + 0x6000
QUEUE_DATA = v.RAM + 0x6100
RANGES = [(0xbb22d8, 0xbb2378), (0xbb34d4, 0xbb3634),
          (0xbb366e, 0xbb367a), (0xbb4c8e, 0xbb4d5a),
          (0xbb6ddc, 0xbb6e98), (0x54ef64, 0x54ef96),
          (0xb1920a, 0xb19222), (0x49f16c, 0x49f1e4),
          (0xb190d6, 0xb191aa)]
DIAGNOSTICS = [0x4a2620, 0x4a23b0, 0x774d16, 0x4a2cf0, 0x4a2e24,
               0x4a3204, 0x4a33ac, 0x4a34e8, 0x4a35f8, 0x4a3730,
               0x4a3908, 0x4a3c14, 0x4a3e18, 0x4a4264, 0x4a4978,
               0x4a4bd0, 0x4a51ec, 0x4a54e0]


class Completion(release.Native):
    def __init__(self, cp):
        super().__init__(cp)
        self.status = {}
        self.flags = {0x32: 0, 0x33: 0}
        self.timeline = []
        self.locks = {}
        self.timed_result = 0
        self.blocking_result = 0
        self.signal_result = 0
        self.wait_success_requires_flags = True
        self.channel = None

    def code(self, u, pc, size, unused):
        a = [u.reg_read(v.reg(i)) for i in range(4)]
        if pc == 0x5f267c:
            self.ret(0)
        elif pc == 0x5ee450:
            assert 0x54 <= a[0] <= 0x57
            assert not self.locks.get(a[0], False)
            self.locks[a[0]] = True
            self.ret()
        elif pc == 0x5ee8a8:
            assert self.locks[a[0]]
            self.locks[a[0]] = False
            self.ret()
        elif pc == 0xb61704:
            assert a[0] in self.status
            self.ret(self.status[a[0]])
        elif pc == 0xb61708:
            # Device interrupt acknowledgment, not plain RAM semantics.
            assert a[1] in (1, 6, 7)
            self.timeline.append(['ack_fixture', a[0], a[1]])
            self.ret()
        elif pc == 0x54df8c:
            # Dispatcher attempts to start another transfer AFTER callback.
            self.timeline.append(['start_next_boundary', a[0], a[1]])
            self.ret()
        elif pc == 0xb4361c:
            self.timeline.append(['trace', *a])
            self.ret()
        elif pc == 0xb4457a:
            self.timeline.append(['error_log', *a])
            self.ret()
        elif pc == 0x5e9a7c:
            self.timeline.append(['signal', a[0], a[1], self.signal_result])
            if self.signal_result == 0:
                self.flags[a[0]] |= a[1]
            self.ret(self.signal_result)
        elif pc == 0x5ea52c:
            timeout = v.word(u, u.reg_read(ar.UC_ARM_REG_SP))
            assert timeout == 3000 and a[2] == 2
            self.timeline.append(['timed_wait', a[0], a[1], timeout, self.timed_result])
            if self.timed_result == 0 and self.wait_success_requires_flags:
                assert self.flags[a[0]] & a[1] == a[1]
            v.put(u, a[3], self.flags[a[0]])
            self.ret(self.timed_result)
        elif pc == 0x5ea9f0:
            self.timeline.append(['inspect_event_fixture', a[0]])
            u.mem_write(a[1], struct.pack('<2I', 0, self.flags[a[0]]))
            self.ret()
        elif pc in DIAGNOSTICS:
            self.timeline.append(['diagnostic_boundary', hex(pc)])
            self.ret()
        elif pc == 0x5e9f9c:
            assert a[2] == 2
            self.timeline.append(['blocking_wait', a[0], a[1], self.blocking_result])
            if self.blocking_result == 0:
                # Explicit OS completion fixture after diagnostic/timeout.
                self.flags[a[0]] |= a[1]
            v.put(u, a[3], self.flags[a[0]])
            self.ret(self.blocking_result)
        elif pc == 0x5e9cc4:
            self.timeline.append(['clear_flags', a[0], a[1]])
            self.flags[a[0]] &= a[1]
            self.ret()
        else:
            assert any(lo <= pc < hi for lo, hi in RANGES), hex(pc)

    def register(self, channel, event):
        callback = {0x32: 0xb1920b, 0x33: 0xb19217}[event]
        self.u.mem_write(PARAMS, struct.pack('<2I', 2, callback))
        self.call(0xbb22d8, channel, PARAMS)
        assert not any(self.locks.values())

    def configure_gate(self, channel, completed, active=15):
        base = QUEUE_DATA + channel * 16
        v.put(self.u, QUEUES + channel * 8, base)
        self.u.mem_write(QUEUES + channel * 8 + 4, b'\1')
        mask = sum(1 << (12 + 4 * i) for i in range(4) if active & (1 << i))
        v.put(self.u, base, mask)
        for output in range(3, 7):
            ident = self.call(0x54ef64, output, channel)
            self.status[ident] = int(bool(completed & (1 << (output - 3))))
        v.put(self.u, 0x1a7e578 + channel * 8, 0x12345678)
        self.channel = channel

    def wait(self, event, mask):
        v.put(self.u, v.SP, 1)  # fifth argument enables diagnostic trace
        result = self.call(0xb190d6, 0x12345678, event, mask, 0)
        assert not any(self.locks.values())
        return result


def verify_wait_predicate(cp):
    # Execute two tiny native ARM snippets, separate from the OS fixture above.
    # Scheduler/locks are outside scope; actual mode-bit and ALL/ANY comparison
    # instructions choose success vs the wait/timeout branch.
    u = v.n.cp_machine()
    u.mem_write(0x108000, cp)
    def stop(u, pc, size, unused):
        if pc in (0x5ea720, 0x5ea7a4):
            u.emu_stop()
        else:
            assert 0x5ea6fc <= pc < 0x5ea720, hex(pc)
    count = 0
    for mode, flags, wanted in itertools.product((1, 2), range(16), (1, 2, 4, 8, 15)):
        u.reg_write(ar.UC_ARM_REG_CPSR, 0x13)
        u.reg_write(v.reg(4), mode)
        u.emu_start(0x5ea620, 0x5ea624, count=1)
        assert u.reg_read(ar.UC_ARM_REG_LR) == mode & 1
        u.reg_write(v.reg(0), PARAMS)
        u.reg_write(v.reg(10), wanted)
        v.put(u, PARAMS + 12, flags)
        hook = u.hook_add(UC_HOOK_CODE, stop)
        u.emu_start(0x5ea6fc, v.STOP, count=20)
        u.hook_del(hook)
        success = bool(flags & wanted) if mode == 1 else flags & wanted == wanted
        assert u.reg_read(ar.UC_ARM_REG_PC) == (0x5ea7a4 if success else 0x5ea720)
        count += 1
    return count


def main():
    cp = (HERE / 'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    digest = hashlib.sha256(cp).hexdigest()
    assert digest == release.EXPECTED_CP
    # Callback identity and event-mask table come from candidate bytes.
    at = 0x49f1e4 - 0x108000
    name = b'IspCallbackEnd_VFX_Base\0'
    assert cp[at:at + len(name)] == name
    bits = struct.unpack_from('<4I', cp, 0x49f1fc - 0x108000)
    assert bits == (0x1000, 0x2000, 0x4000, 0x8000)

    predicate_cases = verify_wait_predicate(cp)
    callback_cases = []
    for event, channel, error in itertools.product((0x32, 0x33), range(4), (0, 1)):
        n = Completion(cp)
        n.call(0xb1920a if event == 0x32 else 0xb19216, error, 0x1234, channel + 3)
        assert n.flags[event] == (0 if error else bits[channel])
        callback_cases.append({'event': event, 'channel': channel, 'error': error,
                               'signaled': n.flags[event]})
    for event in (0x32, 0x33):
        for invalid in (0, 2, 7, 0xffffffff):
            n = Completion(cp)
            n.call(0xb1920a if event == 0x32 else 0xb19216, 0, 0, invalid)
            assert not any(n.flags.values())
        n = Completion(cp)
        n.signal_result = -18
        n.call(0xb1920a if event == 0x32 else 0xb19216, 0, 0, 3)
        assert not any(n.flags.values())
        assert any(x[0] == 'error_log' for x in n.timeline)

    gates = []
    for channel, active, completed in itertools.product(range(4), range(16), range(16)):
        n = Completion(cp)
        n.register(channel, 0x32)
        n.configure_gate(channel, completed, active)
        n.call(0xbb34d4, channel)
        # Back-edge bb6e82 targets bb6e4e, after r5 initialization. Any
        # incomplete active output therefore keeps the whole channel pending.
        dispatched = completed & active == active
        assert n.flags[0x32] == (bits[channel] if dispatched else 0)
        assert v.word(n.u, SLOTS + channel * 24) == (0 if dispatched else 1)
        assert bool([x for x in n.timeline if x[0] == 'start_next_boundary']) == dispatched
        assert not any(n.locks.values())
        gates.append({'channel': channel, 'active_output_mask': active,
                      'injected_output_mask': completed, 'callback_dispatched': dispatched})

    partials = []
    for channel in range(4):
        n = Completion(cp)
        n.register(channel, 0x32)
        n.configure_gate(channel, 7)
        n.call(0xbb34d4, channel)
        assert n.flags[0x32] == 0
        assert v.word(n.u, QUEUE_DATA + channel * 16) == 1 << 24
        # Prior completed outputs no longer need their status to remain set.
        for output in range(3, 7):
            ident = n.call(0x54ef64, output, channel)
            n.status[ident] = int(output == 6)
        n.call(0xbb34d4, channel)
        assert n.flags[0x32] == bits[channel]
        assert n.u.mem_read(QUEUES + channel * 8 + 4, 1) == b'\0'
        partials.append({'channel': channel, 'partial_progress_retained': True,
                         'callback_only_after_final_output': True})

    # Both alternating photo contexts queue through the two native slots. No
    # second event may be attributed to the first slot, and duplicate dispatch
    # after the slots are empty must not signal a fresh photo event.
    queued = []
    for channel in range(4):
        n = Completion(cp)
        n.register(channel, 0x32)
        n.register(channel, 0x33)
        assert v.word(n.u, SLOTS + channel * 24 + 12) == 1
        n.configure_gate(channel, 15)
        n.call(0xbb34d4, channel)
        assert n.flags == {0x32: bits[channel], 0x33: 0}
        assert v.word(n.u, SLOTS + channel * 24 + 8) == 0xb19217
        n.configure_gate(channel, 15)
        n.call(0xbb34d4, channel)
        assert n.flags == {0x32: bits[channel], 0x33: bits[channel]}
        n.flags = {0x32: 0, 0x33: 0}
        n.configure_gate(channel, 15)
        n.call(0xbb34d4, channel)
        assert not any(n.flags.values())
        queued.append({'channel': channel, 'two_slot_order_verified': True,
                       'empty_slot_does_not_signal': True})

    waits = []
    for event, scenario in itertools.product((0x32, 0x33),
            ('success', 'timeout_then_complete', 'timeout_then_wait_error', 'other_wait_error')):
        n = Completion(cp)
        if scenario == 'success':
            for channel in range(4):
                n.register(channel, event)
                n.configure_gate(channel, 15)
                n.call(0xbb34d4, channel)
            assert n.flags[event] == 0xf000
        elif scenario.startswith('timeout'):
            n.timed_result = -50
            n.blocking_result = -18 if scenario.endswith('error') else 0
        else:
            n.timed_result = -18
        result = n.wait(event, 0xf000)
        assert result == 0  # Native wrapper returns clear_flags result.
        assert n.flags[event] == 0
        diagnostics = [x[1] for x in n.timeline if x[0] == 'diagnostic_boundary']
        assert len(diagnostics) == (len(DIAGNOSTICS) if scenario.startswith('timeout') else 0)
        waits.append({'event': event, 'scenario': scenario, 'wrapper_result': result,
                      'timeline': n.timeline})
    report = {'status': 'NOT_READY_TO_FLASH', 'camera_io': False,
              'cp_sha256': digest,
              'test_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'native_os_wait_predicate_cases': predicate_cases, 'callback_cases': callback_cases, 'invalid_callback_inputs': 8,
              'event_signal_errors': 2, 'gate_cases': gates, 'queued_contexts': queued,
              'wait_cases': waits, 'partial_completion_cases': partials,
              'native_ranges': [[hex(a), hex(b)] for a, b in RANGES],
              'fixtures': ['OS locks, trace/log, event flag operations and waits',
                           'hardware interrupt status and acknowledgment',
                           'diagnostics and start-next-transfer boundary'],
              'limitations': ['arbitrary injected hardware status ordering is not proved reachable',
                              'OS errors are injected and their runtime likelihood is unknown',
                              'callback notification is not proof of LUT reader/cache/DMA quiescence',
                              'third concurrent registration and interrupt/task interleavings are unverified',
                              'no candidate patch or production resource release added']}
    out = HERE / 'dev-menu-03/vfx-completion-verification.json'
    out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(out), 'callback_cases': len(callback_cases),
                      'native_wait_predicates': predicate_cases, 'gate_cases': len(gates), 'partial_cases': len(partials), 'queued_contexts': len(queued),
                      'wait_cases': len(waits), 'status': report['status']}))


if __name__ == '__main__':
    main()
