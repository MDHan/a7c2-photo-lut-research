"""Native LUT worker dispatch/wait/callback tests, offline OS/DMA boundaries."""
import hashlib
import json
from pathlib import Path
import struct

import verify_resource_release as release
from unicorn import arm_const as ar

v = release.v
HERE = Path(__file__).resolve().parent
DMA_DESC = 0x262cb50
CALLBACK_GLOBAL = 0x1a797d8
ISR = 0xb831f8
TRAMPOLINE = v.STOP + 0x100
EXTRA_RANGES = [(0x53533c, 0x5353f4), (0xb82c22, 0xb82cb6),
                (0xb82dbe, 0xb82e00), (0xb833f4, 0xb8346e),
                (0xb83062, 0xb83282), (0x5810bc, 0x58123e),
                (0xbf6cbc, 0xbf6d0c)]


class Worker(release.Native):
    def __init__(self, cp, mode):
        super().__init__(cp)
        self.u.mem_map(0x2600000, 0x100000)
        self.mode = mode
        self.timeline = []
        self.callback_results = []
        self.context = None
        self.registered = None
        self.waits = []
        self.worker_result = None
        self.receives = 0
        if mode == 'busy_registration':
            # Native channel-address tables; only hardware register contents
            # are fixtures. Execute the real registration busy rejection.
            self.u.mem_map(0xf1058000, 0x2000)
            slot = v.word(self.u, 0xcec210 + 5 * 4)
            bank = v.word(self.u, 0xcec250 + 5 * 4)
            assert bank in (0, 1) and slot < 8
            v.put(self.u, 0xf1058000 + bank * 0x1000 + slot * 0x20 + 0x110, 1)
            v.put(self.u, 0x1a80c90 + 5 * 4, 0x99887766)

    def code(self, u, pc, size, unused):
        args = [u.reg_read(v.reg(i)) for i in range(4)]
        if pc == 0x5353f4:
            # The real b833f4 created these three register-transfer entries.
            # Physical translation/cache maintenance is the DMA boundary here.
            assert args[1] == DMA_DESC
            channel, count, entries = struct.unpack('<3I', u.mem_read(args[0], 12))
            assert (channel, count) == (0, 3)
            transfers = [struct.unpack('<3I', u.mem_read(entries + i * 0x8c, 12)) for i in range(3)]
            assert [row[1:] for row in transfers] == [(0x400, 1), (0x410, 1), (0x414, 1)]
            self.timeline.append('dma_descriptor_boundary')
            self.ret()
            return
        if pc == 0x56309c:
            assert args[0] == 0x2ae085d and args[1] in (0, 1000)
            self.waits.append(args[1])
            self.timeline.append('wait_' + str(args[1]))
            if args[1] == 0:
                self.ret(-1 if self.mode == 'initial_wait_failure' else 0)
            elif self.mode == 'timeout':
                self.ret(-1)
            else:
                assert self.registered == ISR | 1
                assert self.context is None
                # Inject one asynchronous completion at the wait boundary.
                # Execute the native ISR and native application callback, then
                # restore the waiting CPU context without reverting memory.
                self.context = u.context_save()
                u.reg_write(v.reg(0), 1 if self.mode == 'dma_error' else 0)
                u.reg_write(ar.UC_ARM_REG_LR, TRAMPOLINE | 1)
                u.reg_write(ar.UC_ARM_REG_PC, ISR | 1)
            return
        if pc == TRAMPOLINE:
            assert self.context is not None
            u.context_restore(self.context)
            self.context = None
            self.timeline.append('wait_completed')
            self.ret()
            return
        if pc == 0x5810bc:
            assert args[0] == 5 and args[2] == ISR | 1
            if self.mode == 'busy_registration':
                self.timeline.append('native_registration_busy_check')
                return
            self.registered = args[2]
            self.timeline.append('register_completion')
            self.ret(-1 if self.mode == 'registration_failure' else 0)
            return
        if pc == 0xbf6fa4:
            assert args[:2] == [5, DMA_DESC]
            self.timeline.append('submit_dma')
            self.ret(-1 if self.mode == 'submission_failure' else 0)
            return
        if pc == 0x563308:
            assert args[0] == 0x2ae085d
            self.timeline.append('signal_completion')
            self.ret()
            return
        if pc == 0x5653a8:
            assert args[0] == 0x2ae085a and args[2] == 0xffffffff
            self.receives += 1
            self.timeline.append('receive_' + str(self.receives))
            if self.receives == 2:
                u.emu_stop()
            else:
                v.put(u, args[1], release.BUFFER)
                self.ret()
            return
        if pc == 0x565300:
            assert args[:2] == [0x2ae085a, release.BUFFER]
            self.timeline.append('free_message')
            self.ret()
            return
        if pc == 0x4e89f0:
            result = args[0] if args[0] < 0x80000000 else args[0] - 0x100000000
            self.callback_results.append(result)
            self.timeline.append('application_callback_' + str(result))
        if pc == 0xb82df8:
            self.worker_result = args[0]
            self.timeline.append('handler_return')
        if any(lo <= pc < hi for lo, hi in EXTRA_RANGES):
            return
        super().code(u, pc, size, unused)

    def enqueue(self):
        self.u.mem_write(release.REQUEST, struct.pack('<6I', 1, 2, 3, 4, 5, 6))
        assert self.call(0xb79576, 0, release.REQUEST, 0x4e89f1) == 0
        assert len(self.queued) == 1
        assert bytes(self.u.mem_read(release.BUFFER, 0x38)) == self.queued[0]

    def dispatch(self):
        self.enqueue()
        self.call(0x53533c, release.BUFFER)

    def loop_once(self):
        self.enqueue()
        self.u.reg_write(ar.UC_ARM_REG_SP, v.SP)
        self.u.emu_start(0xb82c23, v.STOP, count=30000)
        assert self.receives == 2
        assert self.u.reg_read(ar.UC_ARM_REG_PC) == 0x5653a8
        assert self.timeline[-2:] == ['free_message', 'receive_2']


def main():
    folder = HERE / 'dev-menu-02'
    cp = (folder / 'candidate/cpapp-b.bin').read_bytes()
    assert hashlib.sha256(cp).hexdigest() == release.EXPECTED_CP
    results = []
    expected = {'success': (0, [0], [0, 1000]),
                'dma_error': (0, [-6], [0, 1000]),
                'initial_wait_failure': (-20, [-20], [0]),
                'registration_failure': (-20, [-20], [0]),
                'busy_registration': (-20, [-20], [0]),
                'submission_failure': (-20, [-20], [0]),
                'timeout': (-7, [-7], [0, 1000])}
    for mode, (status, callbacks, waits) in expected.items():
        n = Worker(cp, mode)
        n.dispatch()
        assert n.worker_result == status & 0xffffffff
        assert n.callback_results == callbacks
        assert n.waits == waits
        assert n.u.mem_read(v.PENDING, 1) == b'\0'
        assert v.word(n.u, v.STATE) == (2 if mode == 'success' else 0)
        assert v.word(n.u, CALLBACK_GLOBAL) == 0x4e89f1
        if mode == 'busy_registration':
            assert 'submit_dma' not in n.timeline
            assert v.word(n.u, 0x1a80c90 + 5 * 4) == 0x99887766
        results.append({'mode': mode, 'handler_result': status,
                        'application_callbacks': callbacks, 'wait_arguments': waits,
                        'timeline': n.timeline, 'callback_pointer_retained': True})
    loops = {}
    for mode, (status, callbacks, waits) in expected.items():
        loop = Worker(cp, mode)
        loop.loop_once()
        assert loop.worker_result == status & 0xffffffff
        assert loop.callback_results == callbacks and loop.waits == waits
        timeline = loop.timeline
        assert timeline.index('application_callback_' + str(callbacks[0])) < timeline.index('handler_return')
        assert timeline.index('handler_return') < timeline.index('free_message')
        loops[mode] = timeline
    # Demonstrate the unresolved timeout boundary without assuming hardware
    # can really deliver an old completion after the timeout.
    late = Worker(cp, 'timeout')
    late.dispatch()
    v.put(late.u, v.STATE, 2)
    v.put(late.u, v.DESC, 0x99)
    late.u.mem_write(v.PENDING, b'\1')
    late.call(ISR, 1)
    assert late.callback_results == [-7, -6]
    assert late.u.mem_read(v.PENDING, 1) == b'\0'
    assert v.word(late.u, v.DESC) == 0
    report = {
        'status': 'NOT_READY_TO_FLASH', 'camera_io': False,
        'cp_sha256': release.EXPECTED_CP,
        'source_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                          (Path(__file__), HERE / 'verify_resource_release.py')},
        'dispatch_cases': results, 'native_worker_loops': loops,
        'injected_late_interrupt_after_timeout': {'callbacks': late.callback_results,
                                                  'new_descriptor_cleared': True},
        'findings': ['Native worker waits before receiving the next queued message.',
                     'DMA error callback can coexist with a successful worker wait return.',
                     'Timeout reports -7 through the application callback and retains the callback pointer.',
                     'Native registration rejects busy channel 5 without replacing the hardware callback or submitting DMA.'],
        'boundaries': ['OS queue, event, completion registration and DMA submission are fixtures.',
                       'DMA descriptor physical translation and cache maintenance are intercepted.',
                       'Wait argument 1000 is observed; time units have not been established.',
                       'Late interrupt is injected; hardware cancellation and real timing remain unproven.']}
    (folder / 'queue-completion-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
