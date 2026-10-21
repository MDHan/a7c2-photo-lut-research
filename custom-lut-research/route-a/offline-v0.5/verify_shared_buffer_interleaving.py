"""Adversarial schedule at explicit transport/DMA boundaries; no camera I/O.

Executes dev-menu-03 upload, native receiver, photo bridge/apply/readiness,
and completion callback. Transfer, DMA consumption and VFX submission are
fixtures. A passing test reproduces a missing local guard, NOT a proven
reachable hardware race or a successful JPEG capture.
"""
import hashlib
import importlib.metadata
import json
import struct
from pathlib import Path

from unicorn import UC_HOOK_CODE
from unicorn import arm_const as ar
import build as b
import verify as v
import verify_lut_upload as upload
from verify_upload_guards import Guarded

HERE = Path(__file__).resolve().parent
FOLDER = HERE / 'dev-menu-03'
TARGET = 0x71000000
OBJ = 0x16596d0
sha = lambda data: hashlib.sha256(data).hexdigest()


class Receiver:
    """Persistent native receiver; shared mapping service is a fixture."""
    def __init__(self, cp):
        self.u = u = v.n.cp_machine()
        u.mem_write(0x108000, cp)
        v.put(u, OBJ, 0xffffffff)
        v.put(u, v.G + 0xc0, 17)
        self.mapping_calls = []
        u.hook_add(UC_HOOK_CODE, self.code)

    def code(self, u, pc, size, unused):
        args = [u.reg_read(v.reg(i)) for i in range(4)]
        if pc == 0xb44b96:
            assert args[:2] in ([OBJ, 5], [OBJ, 0xb5])
            self.mapping_calls.append('release_fixture')
            v.put(u, OBJ, 0xffffffff)
        elif pc == 0xb44a2c:
            assert args[:3] == [OBJ, 1, 5]
            self.mapping_calls.append('acquire_fixture')
            u.mem_write(OBJ + 0x10, struct.pack('<Q', TARGET))
        elif pc == 0x61ed00:
            u.mem_write(args[0], bytes(args[1]))
        else:
            assert 0x35c54c <= pc < 0x35c694, hex(pc)
            return
        u.reg_write(v.reg(0), 0)
        u.reg_write(ar.UC_ARM_REG_PC, u.reg_read(ar.UC_ARM_REG_LR))

    def receive(self, message):
        u = self.u
        u.mem_write(v.RAM, message)
        saved = {v.reg(i): 0x11800000 + i for i in range(4, 12)}
        for reg, value in saved.items(): u.reg_write(reg, value)
        u.reg_write(v.reg(0), v.RAM)
        u.reg_write(ar.UC_ARM_REG_SP, v.SP)
        u.reg_write(ar.UC_ARM_REG_LR, v.STOP | 1)
        u.emu_start(0x35c54d, v.STOP, count=5000)
        assert u.reg_read(ar.UC_ARM_REG_PC) == v.STOP
        assert u.reg_read(ar.UC_ARM_REG_SP) == v.SP
        assert all(u.reg_read(reg) == value for reg, value in saved.items())
        return bytes(u.mem_read(v.G + 0x68, 96))


class Transport(Guarded):
    def __init__(self, ap, manifest, payload, special, on_transfer):
        self.on_transfer = on_transfer
        super().__init__(ap, manifest, payload, special=special)

    def code(self, u, pc, size, unused):
        if pc == 0x34cb5e8:
            # Model the transport copying to the same target handle before
            # returning completion. No asynchronous transport internals run.
            descriptor = struct.unpack('<6I', u.mem_read(u.reg_read(upload.menu.X(0)), 24))
            assert descriptor[2] == 0x202 and descriptor[3] == 0
            payload = bytes(u.mem_read(upload.MAPPING, descriptor[4]))
            self.on_transfer(payload)
        super().code(u, pc, size, unused)


def scenario(ap, cp, manifest, special, schedule):
    size = 48124 if special else 48000
    before = bytes((i * 17 + 3) % 256 for i in range(size))
    after = bytes((i * 29 + 7) % 256 for i in range(size))
    first = Guarded(ap, manifest, before, special=special)
    message = first.execute(lut=3)
    receiver = Receiver(cp)
    context = receiver.receive(message)
    assert v.word(receiver.u, v.G + 0xc0) == 18
    assert receiver.mapping_calls == ['release_fixture', 'release_fixture', 'acquire_fixture']
    receiver.mapping_calls.clear()

    c = v.Capture(cp, manifest)
    u = c.u
    u.mem_map(TARGET, 0xc000)
    u.mem_write(TARGET, before)
    u.mem_write(v.G + 0x68, context)
    v.put(u, v.STATE, 1)
    v.put(u, v.RES, 0x8833)
    events, observed, messages = [], [], []
    callback_return = None
    callback_count = 0
    terminal = None
    submits = 0
    ranges = [(b.CP_CODE, b.CP_CODE + manifest['placement']['cp_bytes']),
              (0x48c740, 0x48c74e), (0x4e8a5c, 0x4e8b22),
              (0xb31a54, 0xb31aac), (0x4e876c, 0x4e8970),
              (0x4e89f0, 0x4e8a40)]

    def transfer(payload):
        assert payload == after
        assert v.word(u, v.G + 0xc0) == 18
        assert v.word(u, v.TOKEN) == 18
        u.mem_write(TARGET, payload)
        events.append('transport_overwrite_fixture_before_4155_delivery')

    def hook(u, pc, insn_size, unused):
        nonlocal callback_return, callback_count, terminal, submits
        def ret(value=0):
            u.reg_write(v.reg(0), value)
            u.reg_write(ar.UC_ARM_REG_PC, u.reg_read(ar.UC_ARM_REG_LR))
        if pc in (0x48c778, 0x48c790, 0x48c74e):
            terminal = hex(pc)
            u.emu_stop()
            return
        if callback_return == pc:
            # Complete the loader fixture after the actual native callback.
            # The callback's return register is not the loader's status ABI.
            u.reg_write(v.reg(0), 0)
            callback_return = None
        if pc in (0x54e15c, 0x54e398):
            assert pc == (0x54e398 if special else 0x54e15c)
            ptr = u.reg_read(v.reg(0))
            assert struct.unpack('<QI', u.mem_read(ptr, 12)) == (TARGET, 48000)
            callback = u.reg_read(v.reg(3 if special else 2))
            assert callback == 0x4e89f1
            if special:
                ptr = u.reg_read(v.reg(1))
                assert struct.unpack('<QI', u.mem_read(ptr, 12)) == (TARGET + 48000, 124)
            events.append('native_loader_boundary_with_snapshot_token_18')
            if schedule != 'unchanged':
                h = Transport(ap, manifest, after, special, transfer)
                messages.append(h.execute(lut=18))
                assert h.timeline.index('interchip_completion_fixture') < h.timeline.index('send_4155_fixture')
                events.append('ap_4155_send_collected_delivery_deferred')
                if schedule == 'delivered_before_consumption':
                    updated = receiver.receive(messages[-1])
                    assert v.word(receiver.u, v.G + 0xc0) == 19
                    # Transfer the receiver's actual descriptor writes between
                    # the two independent emulators; no CP threads simulated.
                    u.mem_write(v.G + 0x68, updated)
                    events.append('native_receiver_result_applied_token_19')
            observed.append(sha(bytes(u.mem_read(TARGET, size))))
            events.append('dma_consumption_fixture')
            callback_return = u.reg_read(ar.UC_ARM_REG_LR) & ~1
            u.reg_write(v.reg(0), 0)
            u.reg_write(ar.UC_ARM_REG_PC, callback)
            return
        if pc == 0x4e89f0:
            callback_count += 1
            events.append('native_success_callback')
        if pc == 0x480f28:
            c.check_args()
            submits += 1
            events.append('vfx_submit_fixture')
            u.mem_write(c.result, struct.pack('<II', 1, 0))
            ret()
            return
        if pc in (0xb4457a, 0xb4361c):
            ret()
            return
        assert any(lo <= pc < hi for lo, hi in ranges), hex(pc)

    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(b.CP_ENTRY | 1, v.STOP, count=50000)
    assert terminal is not None and callback_count == 1
    assert u.reg_read(ar.UC_ARM_REG_SP) == v.SP
    assert all(u.reg_read(reg) == value for reg, value in c.saved.items())
    assert observed == [sha(before if schedule == 'unchanged' else after)]
    if schedule == 'delivered_before_consumption':
        assert terminal == '0x48c778' and submits == 0
        assert v.word(u, c.result + 4) == 0xc17e0003
        assert all(v.word(u, address + 0x234) == 0 for address in v.RAW)
    else:
        assert terminal == '0x48c790' and submits == 1
        assert [v.word(u, address + 0x234) for address in v.RAW] == [1, 0, 0, 0]
        assert v.word(u, v.G + 0xc0) == v.word(u, v.TOKEN) == 18
        assert v.word(u, v.G + 0x684) == 17
    if schedule == 'deferred_delivery':
        receiver.receive(messages[-1])
        assert v.word(receiver.u, v.G + 0xc0) == 19
        events.append('native_receiver_after_photo_decision_token_19')
    assert receiver.mapping_calls == [], 'same-handle receiver unexpectedly remapped'
    for i, address in enumerate(v.RAW):
        now = bytearray(u.mem_read(address, 0x320))
        now[0x234:0x238] = c.original[i][0x234:0x238]
        assert now == c.original[i]
    return {'special': special, 'schedule': schedule, 'events': events,
            'loaded_fixture_sha256': observed[0], 'old_payload_sha256': sha(before),
            'new_payload_sha256': sha(after), 'terminal': terminal,
            'vfx_submits': submits, 'same_handle_remap_calls': receiver.mapping_calls,
            'error': hex(v.word(u, c.result + 4)),
            'local_guard_misses_overwrite': schedule == 'deferred_delivery'}


def main():
    manifest = json.loads((FOLDER / 'manifest.json').read_text())
    ap, cp = [(FOLDER / 'candidate' / name).read_bytes() for name in ('appFw.so', 'cpapp-b.bin')]
    assert sha(ap) == '5e0741cf58f4125f7b6f5950b5d13d47be025052c9dcc1a799e2ce004cd32c93'
    assert sha(cp) == upload.EXPECTED_CP
    cases = [scenario(ap, cp, manifest, special, schedule)
             for special in (False, True)
             for schedule in ('unchanged', 'deferred_delivery', 'delivered_before_consumption')]
    assert (FOLDER / 'candidate/appFw.so').read_bytes() == ap
    assert (FOLDER / 'candidate/cpapp-b.bin').read_bytes() == cp
    report = {'status': 'LOCAL_GUARD_COUNTEREXAMPLE_REPRODUCED', 'readiness': 'NOT_READY_TO_FLASH',
              'camera_io': False, 'hardware_schedule_reachability_proven': False,
              'candidate_sha256': {'appFw.so': sha(ap), 'cpapp-b.bin': sha(cp)},
              'unicorn_version': importlib.metadata.version('unicorn'),
              'source_sha256': {name: sha((HERE / name).read_bytes()) for name in
                                (Path(__file__).name, 'verify_upload_guards.py', 'verify_lut_upload.py',
                                 'verify_menu.py', 'verify.py', 'build.py')},
              'cases': cases,
              'boundaries': ['file IO and mapping are fixtures',
                             'owner reservation supplied as a precondition; native acquire not executed',
                             'transfer completion and destination visibility are injected',
                             'CP receiver and capture execute in separate machines; descriptor writes copied',
                             'driver DMA consumption and VFX acceptance are fixtures',
                             'native completion callback invoked synchronously after fixture consumption',
                             'no actual threads, transport blocking, cache coherence, ISP or JPEG encoding'],
              'conclusion': 'Generation checks alone do not protect the shared bytes; establish serialization or immutable-buffer ownership before flash readiness.'}
    path = FOLDER / 'shared-buffer-interleaving-verification.json'
    path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'cases': len(cases), 'counterexamples': sum(x['local_guard_misses_overwrite'] for x in cases),
                      'readiness': report['readiness'], 'report': str(path)}))


if __name__ == '__main__':
    main()
