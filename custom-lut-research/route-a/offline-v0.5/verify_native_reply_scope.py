"""Offline native CP deferred-reply scope; no transport or camera access.

Run the 4160 receiver, pending-to-active fragment, and actual reply callback.
The snapshot getter, logger and outgoing transport are explicit fixtures.
"""
import hashlib
import json
import struct
from pathlib import Path
from unicorn import UC_HOOK_CODE
from unicorn import arm_const as ar
import verify as v

HERE = Path(__file__).resolve().parent
PENDING, ACTIVE, RESPONSE = 0x165b498, 0x165b488, 0x186fd60
REQUEST, CONTEXT, DETAIL = v.RAM + 0x100, v.RAM + 0x1000, v.RAM + 0x2000
CALLBACK = 0x35a6b5


class Reply:
    def __init__(self, cp):
        self.u = u = v.n.cp_machine()
        u.mem_write(0x108000, cp)
        self.logs = 0
        self.sent = []
        self.transport_result = 0
        self.fragment = False
        u.hook_add(UC_HOOK_CODE, self.code)

    def code(self, u, pc, size, unused):
        if self.fragment and pc == 0x8dada0:
            u.emu_stop()
            return
        args = [u.reg_read(v.reg(i)) for i in range(4)]
        if pc == 0xb4457a:
            self.logs += 1
            result = 0
        elif pc == 0xb2ddb4:
            result = CONTEXT
        elif pc == 0xb20bce:
            assert args[0] == RESPONSE
            result = 0
        elif pc == 0x4b3c48:
            assert args[:3] == [RESPONSE, 20, 0x90030001]
            assert v.word(u, ACTIVE + 12) == 0
            self.sent.append(bytes(u.mem_read(RESPONSE, 20)))
            result = self.transport_result
        else:
            ranges = [(0x35a650, 0x35a694), (0x35448c, 0x3544da),
                      (0xbec02a, 0xbec030), (0x8dad78, 0x8dada0),
                      (0x8db16a, 0x8db1b8), (0x35a6b4, 0x35a75c),
                      (0x8daa14, 0x8daa4e)]
            assert any(a <= pc < z for a, z in ranges), hex(pc)
            return
        u.reg_write(v.reg(0), result & 0xffffffff)
        u.reg_write(ar.UC_ARM_REG_PC, u.reg_read(ar.UC_ARM_REG_LR))

    def run(self, start, *args):
        u = self.u
        saved = {v.reg(i): 0x11800000 + i for i in range(4, 12)}
        for reg, value in saved.items():
            u.reg_write(reg, value)
        for i, value in enumerate(args):
            u.reg_write(v.reg(i), value)
        u.reg_write(ar.UC_ARM_REG_SP, v.SP)
        u.reg_write(ar.UC_ARM_REG_LR, v.STOP | 1)
        u.emu_start(start | 1, v.STOP, count=10000)
        assert u.reg_read(ar.UC_ARM_REG_PC) == v.STOP
        assert u.reg_read(ar.UC_ARM_REG_SP) == v.SP
        assert all(u.reg_read(reg) == value for reg, value in saved.items())
        return u.reg_read(v.reg(0))

    def request(self, serial):
        u = self.u
        v.put(u, REQUEST - 12, 0x90030001)
        u.mem_write(REQUEST, struct.pack('<BBHI', 5, 0, 0x4160, serial))
        assert self.run(0x35a650, REQUEST) == 1

    def promote(self):
        # A fragment only: the surrounding snapshot copy/scheduler is not run.
        self.fragment = True
        self.u.emu_start(0x8dad79, v.STOP, count=100)
        assert self.u.reg_read(ar.UC_ARM_REG_PC) == 0x8dada0
        self.fragment = False


def main():
    cp = (HERE / 'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    digest = hashlib.sha256(cp).hexdigest()
    assert digest == '48ff01e346ac74e78b61f811725c0bd95ab2712938b55ad607a5b2f54a3bf4e1'
    cases = []
    # Each busy combination executes the real registration and promotion.
    for pending_busy in (False, True):
        for active_busy in (False, True):
            h = Reply(cp)
            u = h.u
            old = struct.pack('<4I', 0x40000001, 0x77, 0x90030001, CALLBACK)
            if pending_busy:
                u.mem_write(PENDING, old)
            if active_busy:
                u.mem_write(ACTIVE, old)
            h.request(0x1234)
            pending = bytes(u.mem_read(PENDING, 16))
            expected = old if pending_busy else struct.pack('<4I', 0x41600001, 0x1234, 0x90030001, CALLBACK)
            assert pending == expected
            assert h.logs == (1 if pending_busy or active_busy else 0)
            h.promote()
            assert bytes(u.mem_read(ACTIVE, 16)) == (old if active_busy else expected)
            assert v.word(u, PENDING + 12) == (CALLBACK if active_busy else 0)
            cases.append({'pending_busy': pending_busy, 'active_busy': active_busy,
                          'request_return': 1, 'new_request_saved': not pending_busy,
                          'promoted': not active_busy})
    responses = []
    for available in (False, True):
        for send_result in (0, -7):
            h = Reply(cp)
            u = h.u
            h.request(0x4321)
            h.promote()
            v.put(u, CONTEXT + 0x54, DETAIL)
            if available:
                u.mem_write(DETAIL + 2, b'\x01')
                u.mem_write(DETAIL + 0x3f, b'\x01')
                u.mem_write(DETAIL + 0x1e, b'\x01')
                u.mem_write(DETAIL + 0x20, struct.pack('<HH', 640, 480))
            h.transport_result = send_result
            assert h.run(0x8db16a) == (send_result & 0xffffffff)
            assert len(h.sent) == 1
            msg = h.sent[0]
            assert struct.unpack_from('<BBHIIHHH', msg) == (1, 0, 0x4160, 0x4321, 0xf000,
                                                          640 if available else 0,
                                                          480 if available else 0,
                                                          0 if available else 1)
            assert v.word(u, ACTIVE + 12) == 0
            h.run(0x8db16a)
            assert len(h.sent) == 1
            responses.append({'available': available, 'send_result_fixture': send_result,
                              'reply_hex': msg.hex(), 'slot_cleared_before_send': True,
                              'second_poll_retried_send': False})
    report = {'status': 'NATIVE_DEFERRED_REPLY_SCOPE_OFFLINE_VERIFIED', 'camera_io': False,
              'cp_sha256': digest, 'registration_cases': cases, 'response_cases': responses,
              'limitations': ['4160 sample only, not a new LUT protocol',
                             'promotion fragment bypasses surrounding snapshot and scheduling',
                             'snapshot getter, logger, message preprocessor and send are fixtures',
                             'no AP receive/future completion, timeout, concurrency or hardware delivery'],
              'source_sha256': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                for name in ('verify_native_reply_scope.py', 'verify.py')}}
    out = HERE / 'lifecycle-dev/native-reply-scope.json'
    out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'registration_cases': len(cases), 'response_cases': len(responses), 'report': str(out)}))


if __name__ == '__main__':
    main()
