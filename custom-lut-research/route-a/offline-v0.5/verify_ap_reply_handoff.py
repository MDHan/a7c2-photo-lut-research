"""Cooperatively execute native AP send/wait/receive/get for CP 4160 replies.

No real threads, IPC, file/device access. Allocation, RB tree mechanics,
TLS resolution, pthread_once dispatch, futex wake and exception_ptr services
are fixtures. Native promise fulfillment, lookup, wait and parsing execute.
"""
import hashlib
import io
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from verify_menu import Native, RAM, STACK, STOP, X, a
from verify_native_reply_scope import Reply, CONTEXT, DETAIL
import verify as cpv

HERE = Path(__file__).resolve().parent
FUTURE, TLS, OBJECT, NODE = [RAM + x for x in (0x1000, 0xf000, 0x1200, 0x1300)]
VT, PACKET, INPUT, OUTPUT = [RAM + x for x in (0x1400, 0x2000, 0x3000, 0x3100)]
TREE, TREE_MUTEX, SEND_MUTEX = 0x91166b0, 0x9116870, 0x91165a0


class Handoff(Native):
    def __init__(self, raw, reply):
        super().__init__(raw)
        self.reply = reply
        self.phase = 'send'
        self.held = set()
        self.trace = []
        self.promise = None
        self.request = None
        self.stop_reason = None
        self.write(TREE, bytes(0x30))
        self.write(FUTURE, struct.pack('<QQIIQ', VT, 0, 0, 0, 0))
        self.write(VT, bytes(0x20))
        # Virtual deferred-work callback fixture: a RET instruction.
        self.write(VT + 0x10, struct.pack('<Q', VT + 0x40))
        self.write(VT + 0x40, bytes.fromhex('c0035fd6'))
        # Dynamic TLS descriptor resolver / pthread library presence fixtures.
        for address, value in [(0x5bc2b48, VT + 0x60), (0x5bc2b38, VT + 0x64),
                               (0x5ba42f0, 1), (0x5b4ce28, VT + 0x88)]:
            self.write(address, struct.pack('<Q', value))
        self.u.reg_write(a.UC_ARM64_REG_TPIDR_EL0, TLS)
        self.write(INPUT, struct.pack('<I', 0x2222))
        self.write(OUTPUT, b'\xa5' * 16)

    def pause(self, reason):
        self.stop_reason = reason
        self.u.emu_stop()

    def code(self, u, pc, size, unused):
        x = [u.reg_read(X(i)) for i in range(6)]
        if pc in (VT + 0x60, VT + 0x64):
            self.ret(0x40 if pc == VT + 0x60 else 0x48); return
        if pc == 0x165fa00:
            assert x[:2] == [FUTURE + 0x18, VT + 0x88]
            self.once_return = u.reg_read(a.UC_ARM64_REG_LR)
            assert self.qword(TLS + 0x48) == 0x303cb60
            u.reg_write(a.UC_ARM64_REG_LR, VT + 0x80)
            u.reg_write(a.UC_ARM64_REG_PC, 0x303cb60)
            self.trace.append('pthread_once_dispatch_fixture')
            return
        if pc == VT + 0x80:
            self.put(FUTURE + 0x18, 2)
            u.reg_write(a.UC_ARM64_REG_LR, self.once_return)
            self.ret(); return
        if pc == 0x1660550:
            assert x[0] == FUTURE + 0x10 and self.word(FUTURE + 0x10) == 1
            assert self.qword(FUTURE + 8) == OBJECT
            assert self.qword(OBJECT + 0x10) == PACKET
            self.trace.append('native_promise_ready_futex_notify_fixture')
            self.ret(); return
        if pc == 0x165ffc0:
            assert self.phase == 'send' and x[3:6] == [0, 0, 0]
            assert self.held == {SEND_MUTEX}
            assert self.word(FUTURE + 0x10) == 0x80000000
            self.trace.append('native_wait_reached_without_timeout')
            self.pause('wait'); return
        if self.phase == 'receive' and pc == 0x3531528 and self.trace[-1] == 'reply_consumed':
            self.pause('consumed'); return
        if self.phase == 'receive' and pc == 0x3531660:
            self.pause('unmatched'); return
        if pc == 0x36825d0:
            self.ret(); return
        if pc == 0x34f4fec:
            assert x[1] == 0
            self.promise = x[0]
            self.write(x[0], struct.pack('<QQQ', FUTURE, 0, 0))
            self.ret(); return
        if pc == 0x165fad0:
            assert x[0] in (0x20, 0x30)
            self.ret(OBJECT if x[0] == 0x20 else NODE); return
        if pc == 0x1660560:
            assert x[0] == OBJECT
            self.ret(); return
        if pc == 0x1794224:
            assert x[0] in (TREE_MUTEX, SEND_MUTEX) and x[0] not in self.held
            self.held.add(x[0]); self.ret(); return
        if pc == 0x1794280:
            mutex = self.qword(x[0])
            assert mutex in self.held
            self.held.remove(mutex)
            self.ret(); return
        if pc == 0x165db40:
            assert x[:4] == [1, NODE, TREE + 8, TREE + 8]
            assert self.qword(NODE + 0x28) == self.promise
            assert self.word(NODE + 0x20) & 0xffff == 0x4160
            self.write(NODE + 8, struct.pack('<QQQ', TREE + 8, 0, 0))
            self.write(TREE + 0x10, struct.pack('<QQQ', NODE, NODE, NODE))
            self.ret(); return
        if pc == 0x3599b68:
            assert x[1:4] == [8, 0x90030001, 0x80020002]
            self.request = bytes(u.mem_read(x[0], 8))
            self.write(PACKET, self.request)
            self.ret(PACKET); return
        if pc == 0x165ead0:
            assert x[:2] == [0x90030001, PACKET]
            self.trace.append('send_accepted_fixture')
            self.ret(); return
        if pc == 0x165e940:
            assert x[0] == 0x80020002 and x[2] == 0xffffffff
            self.write(PACKET, self.reply + b'\xa5' * (32 - len(self.reply)))
            self.write(x[1], struct.pack('<Q', PACKET))
            self.ret(); return
        if pc == 0x165f720:
            assert x[0] == PACKET
            self.ret(0x90030001); return
        if pc == 0x165e770:
            self.ret(len(self.reply)); return
        if pc in (0x36825e4, 0x368260c):
            self.ret(); return
        if pc == 0x165d960:
            assert x[0] == NODE
            self.ret(TREE + 8); return
        if pc == 0x1660190:
            assert x[:2] == [NODE, TREE + 8]
            self.write(TREE + 0x10, struct.pack('<QQQ', 0, TREE + 8, TREE + 8))
            self.ret(NODE); return
        if pc == 0x165d4e0:
            assert x[0] == NODE
            self.ret(); return
        if pc == 0x34f3474:
            if self.phase == 'receive':
                self.trace.append('reply_consumed')
            self.ret(); return
        if pc == 0x165d430:
            assert x[0] == OBJECT + 8
            self.ret(1); return
        if pc in (0x165d950, 0x303c7ac):
            self.ret(); return
        if pc == 0x165d3e0:
            assert x[1:3] == [PACKET, 20]
            self.trace.append({'copy_requested': 20, 'reply_bytes': len(self.reply)})
            self.write(x[0], bytes(u.mem_read(x[1], x[2])))
            self.ret(x[0]); return
        if pc == 0x1660350:
            assert x[:2] == [0x80020002, PACKET]
            self.ret(); return
        ranges = [(0x3539070, 0x353912c), (0x35358b8, 0x3535b5c),
                  (0x303cb68, 0x303cb84), (0x34e6700, 0x34e6730),
                  (0x34f4f4c, 0x34f4fec), (0x31018f0, 0x310197c),
                  (0x35314fc, 0x3531660), (0x35316e0, 0x3531710),
                  (0x3531454, 0x35314fc), (VT + 0x40, VT + 0x44),
                  (0x35310c4, 0x3531118), (0x34e6508, 0x34e65f8),
                  (0x303caa4, 0x303cb68), (0x34f340c, 0x34f3474),
                  (0x303c9d4, 0x303c9ec), (0x251cd20, 0x251cd38),
                  (0x34e3458, 0x34e3490)]
        assert any(lo <= pc < hi for lo, hi in ranges), hex(pc)

    def execute(self):
        u = self.u
        saved = {X(i): 0x11800000 + i for i in range(19, 30)}
        for reg, value in saved.items(): u.reg_write(reg, value)
        u.reg_write(a.UC_ARM64_REG_SP, STACK + 0xff00)
        u.reg_write(a.UC_ARM64_REG_LR, STOP)
        u.reg_write(X(0), INPUT); u.reg_write(X(1), OUTPUT)
        u.emu_start(0x3539070, STOP, count=10000)
        assert self.stop_reason == 'wait'
        assert self.request == struct.pack('<BBHI', 5, 0, 0x4160, 0x2222)
        sender = u.context_save()
        self.phase = 'receive'; self.stop_reason = None
        u.reg_write(a.UC_ARM64_REG_SP, STACK + 0x8000)
        u.emu_start(0x35314fc, STOP, count=10000)
        assert self.stop_reason in ('consumed', 'unmatched')
        assert self.held == {SEND_MUTEX}
        if self.stop_reason == 'unmatched':
            assert self.word(FUTURE + 0x10) == 0x80000000
            return {'matched': False, 'sender_resumed': False, 'trace': self.trace}
        assert self.qword(TREE + 0x28) == 0 and self.qword(self.promise) == 0
        u.context_restore(sender)
        self.phase = 'resume'
        # Futex boundary resumes only after native promise publication above.
        self.ret(1)
        u.emu_start(u.reg_read(a.UC_ARM64_REG_PC), STOP, count=10000)
        assert u.reg_read(a.UC_ARM64_REG_PC) == STOP
        assert u.reg_read(a.UC_ARM64_REG_SP) == STACK + 0xff00
        assert all(u.reg_read(reg) == value for reg, value in saved.items())
        assert not self.held
        return {'matched': True, 'sender_resumed': True, 'trace': self.trace,
                'parsed_output': list(struct.unpack('<4I', u.mem_read(OUTPUT, 16)))}


def main():
    ap = (HERE / 'dev-menu-03/candidate/appFw.so').read_bytes()
    cp = (HERE / 'dev-menu-03/candidate/cpapp-b.bin').read_bytes()
    assert hashlib.sha256(ap).hexdigest() == '5e0741cf58f4125f7b6f5950b5d13d47be025052c9dcc1a799e2ce004cd32c93'
    assert hashlib.sha256(cp).hexdigest() == '48ff01e346ac74e78b61f811725c0bd95ab2712938b55ad607a5b2f54a3bf4e1'
    elf = ELFFile(io.BytesIO(ap))
    rela = elf.get_section_by_name('.rela.plt')
    symbols = elf.get_section(rela['sh_link'])
    plt = elf.get_section_by_name('.plt')['sh_addr']
    imports = {plt + 32 + 16*i: symbols.get_symbol(r['r_info_sym']).name
               for i, r in enumerate(rela.iter_relocations())}
    assert '_M_futex_wait_until' in imports[0x165ffc0]
    assert imports[0x165fa00] == 'pthread_once'
    cases = []
    for label, serial, command, length in [('current', 0x2222, 0x4160, 20),
                                          ('stale_parameter', 0x1111, 0x4160, 20),
                                          ('wrong_command', 0x2222, 0x4161, 20),
                                          ('short_reply', 0x2222, 0x4160, 8)]:
        c = Reply(cp)
        c.request(serial); c.promote()
        cpv.put(c.u, CONTEXT + 0x54, DETAIL)
        if label == 'stale_parameter':
            # Distinct callback data makes accepting this injected old response visible.
            for offset in (2, 0x3f, 0x1e): c.u.mem_write(DETAIL + offset, b'\x01')
            c.u.mem_write(DETAIL + 0x20, struct.pack('<HH', 640, 480))
        c.run(0x8db16a)
        reply = bytearray(c.sent[0])
        struct.pack_into('<H', reply, 2, command)
        h = Handoff(ap, bytes(reply[:length]))
        result = h.execute()
        if label == 'current':
            assert result['parsed_output'] == [0, 0, 0, 1]
        elif label == 'stale_parameter':
            assert result['parsed_output'] == [0, 640, 480, 0]
        elif label == 'short_reply':
            assert result['parsed_output'] == [1, 0, 0, 1]
        else:
            assert not result['matched']
        cases.append({'case': label, 'request_parameter': 0x2222,
                      'reply_parameter': serial, **result})
    names = ['verify_ap_reply_handoff.py', 'verify_native_reply_scope.py', 'verify_menu.py', 'verify.py']
    report = {'status': 'AP_REPLY_HANDOFF_SCOPE_OFFLINE_VERIFIED', 'camera_io': False,
              'ap_sha256': hashlib.sha256(ap).hexdigest(), 'cp_sha256': hashlib.sha256(cp).hexdigest(),
              'cases': cases,
              'verified_imports': {hex(address): imports[address] for address in (0x165ffc0, 0x165fa00)},
              'limitations': ['cooperative injected interleaving, not native concurrent scheduling',
                             'TLS resolution, pthread_once dispatch and futex resumption are fixtures; native promise fulfillment and wait predicate execute',
                             'allocation, RB tree insert/erase, exception_ptr, IPC and memcpy services are fixtures',
                             'short payload is padded to a mapped allocation for observation, not an actual out-of-bounds hardware test',
                             'no new LUT protocol, AP timeout handling or runtime reachability proven'],
              'source_sha256': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}}
    out = HERE / 'lifecycle-dev/ap-reply-handoff.json'
    out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'cases': len(cases), 'report': str(out)}))


if __name__ == '__main__': main()
