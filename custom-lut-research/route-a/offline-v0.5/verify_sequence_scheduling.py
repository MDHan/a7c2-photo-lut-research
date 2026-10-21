"""Native AP queue configuration, dependencies and LUT worker execution.

Thread creation, containers, OS synchronization and upload services are explicit
fixtures. This checks the scheduler's local contract, not reachability of a
camera race and not a proof of global capture exclusion.
"""
import hashlib
import json
import struct
from pathlib import Path
from unicorn import arm64_const as a
from verify_menu import Native, RAM, X
from verify_upload_guards import Guarded
import verify_lut_upload as upload

HERE = Path(__file__).resolve().parent
FOLDER = HERE / 'dev-menu-03'
MANAGER, VECTOR = 0x20000000, 0x20011000
TASK, IMPL, NODE = RAM + 0x4000, 0x20010000, 0x20010400
sha = lambda data: hashlib.sha256(data).hexdigest()


class Heap:
    def ensure(self, address, size):
        if MANAGER <= address and address + size <= MANAGER + 0x20000:
            for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
                if page not in self.mapped:
                    self.u.mem_map(page, 4096)
                    self.mapped.add(page)
            return
        super().ensure(address, size)


class Configuration(Heap, Native):
    def __init__(self, raw):
        super().__init__(raw)
        self.edges, self.secondary, self.threads = [], [], []
        self.key = None

    def code(self, u, pc, size, unused):
        args = [u.reg_read(X(i)) for i in range(3)]
        if pc in (0x33710e4, 0x28bb674, 0x165f4d0, 0x34b9370):
            self.ret(); return  # base/lock initialization and boot setup
        if pc in (0x32222f4, 0x322265c):
            assert args[0] == MANAGER + (0x4460 if pc == 0x32222f4 else 0x4498)
            self.key = self.word(args[1])
            self.ret(VECTOR); return  # map[key] container service
        if pc in (0x32224c4, 0x3209c90):
            assert args[0] == VECTOR and self.key is not None
            (self.edges if pc == 0x32224c4 else self.secondary).append((self.key, self.word(args[1])))
            self.key = None
            self.ret(); return  # vector append service
        if pc == 0x36ec384:
            assert args[0] == 0x3209f10
            self.threads.append({'entry': hex(args[0]), 'argument': hex(args[1]),
                                 'thread_parameter': args[2], 'queue': self.word(args[1] + 8)})
            self.ret(0xa000 + len(self.threads)); return
        super().code(u, pc, size, unused)

    def name(self, seq):
        ptr = self.qword(self.qword(0x5b6a0a0) + seq * 8)
        result = bytearray()
        for i in range(200):
            self.ensure(ptr + i, 1)
            c = self.u.mem_read(ptr + i, 1)[0]
            if not c: return result.decode('ascii')
            result.append(c)
        raise AssertionError('unterminated name')

    def queue(self, seq):
        return self.word(self.qword(0x5b809e8) + seq * 4)

    def message_name(self, file_offset, expected):
        command, length, ptr = struct.unpack_from('<IIQ', self.raw, file_offset)
        assert command == expected
        name = self.raw[ptr:self.raw.index(b'\0', ptr)].decode('ascii')
        assert len(name) + 1 == length
        return {'id': hex(command), 'name': name, 'table_file_offset': hex(file_offset)}


class Worker(Heap, Guarded):
    def __init__(self, raw, manifest, special):
        payload = bytes((i * 17 + 3) % 256 for i in range(48124 if special else 48000))
        super().__init__(raw, manifest, payload, special=special)
        self.held, self.worker_events, self.task_locks = set(), [], None
        self.destructed, self.notified, self.terminator_injected = 0, 0, False
        self.header = MANAGER + 0x310

    def enqueue_fixture(self, task):
        head = self.header + 0x10
        self.write(head, struct.pack('<QQQ', NODE, NODE, 1))
        self.write(NODE, struct.pack('<QQQ', head, head, task))

    def code(self, u, pc, size, unused):
        args = [u.reg_read(X(i)) for i in range(3)]
        if pc == 0x2f3a954:
            mutex = self.qword(args[0])
            assert mutex not in self.held
            self.held.add(mutex)
            self.write(args[0] + 8, b'\1')
            self.ret(); return
        if pc == 0x17b0adc:
            mutex = self.qword(args[0])
            assert mutex in self.held
            self.held.remove(mutex)
            self.write(args[0] + 8, b'\0')
            self.ret(); return
        if pc == 0x1794224:
            assert args[0] not in self.held
            self.held.add(args[0]); self.ret(); return
        if pc == 0x1794280:
            mutex = self.qword(args[0])
            assert mutex in self.held
            self.held.remove(mutex); self.ret(); return
        if pc == 0x165e780:
            assert args[0] == NODE
            nxt, prev = self.qword(NODE), self.qword(NODE + 8)
            self.write(prev, struct.pack('<Q', nxt))
            self.write(nxt + 8, struct.pack('<Q', prev))
            self.ret(); return  # std::list unlink
        if pc in (0x165d4e0, 0x35adc1c, 0x3682308, 0x3682348, 0x36eb480, 0x165d990):
            self.ret(); return  # node free, diagnostics and completion signal
        if pc == 0x36eb2fc:
            self.ret(0); return
        if pc == 0x303cc70:
            self.worker_events.append('native_dependency_wait')
        if pc == 0x34289a8:
            self.task_locks = sorted(self.held)
            self.worker_events.append('native_lut_task_started')
        if pc == 0x303c9cc:
            assert args[0] == TASK
            self.notified += 1
            self.worker_events.append('completion_notification_fixture')
            self.ret(); return
        if pc == 0x34284e8:
            assert args[0] == TASK
            self.destructed += 1
            self.worker_events.append('task_destructor_fixture')
            self.ret(); return
        if pc == 0x165e890:
            assert args[:2] == [self.header + 0x58, u.reg_read(a.UC_ARM64_REG_SP) + 0x70]
            assert not self.terminator_injected and self.destructed == self.notified == 1
            assert self.held == {self.header + 0x28}
            self.enqueue_fixture(0)
            self.terminator_injected = True
            self.ret(); return  # wake with a null task, native worker exits
        super().code(u, pc, size, unused)

    def execute_worker(self, system):
        self.task(0x311a63c, system, 12, 3, 1)
        ptr = self.run(0x2887b48)
        self.write(ptr, bytes([int(self.special)]))
        assert self.qword(TASK) == 0x5b3db20
        self.write(TASK + 8, struct.pack('<Q', IMPL))
        self.write(IMPL, bytes(0x1b8))
        self.put(IMPL + 8, 0x1bc)
        self.write(MANAGER, bytes(0x4500))
        self.write(MANAGER + 0x44d0, struct.pack('<QQQ', MANAGER + 0x44d0, MANAGER + 0x44d0, 0))
        self.put(self.header + 8, 0)
        self.enqueue_fixture(TASK)
        self.messages.clear(); self.timeline.clear()
        allowed = upload.RANGES + [(0x34289a8, 0x34289f0), (0x3209d48, 0x3209f10),
                                  (0x303c794, 0x303c7ac), (0x303cb84, 0x303cc78)]
        self.run(0x3209d48, (MANAGER, self.header), allowed)
        assert self.notified == self.destructed == 1 and not self.held
        assert self.task_locks == []
        assert self.terminator_injected and len(self.messages) == 1
        assert self.qword(self.header + 0x88) == 0
        assert self.qword(self.header + 0x20) == 0
        return {'system': system, 'special': self.special,
                'worker_events': self.worker_events, 'task_entry_queue_mutexes_held': self.task_locks,
                'upload_timeline': self.timeline, 'message_sha256': sha(self.messages[0]),
                'worker_returned_and_released_fixture_locks': True}


def main():
    raw = (FOLDER / 'candidate/appFw.so').read_bytes()
    assert sha(raw) == '5e0741cf58f4125f7b6f5950b5d13d47be025052c9dcc1a799e2ce004cd32c93'
    manifest = json.loads((FOLDER / 'manifest.json').read_text())
    c = Configuration(raw)
    c.run(0x33711ec, (MANAGER,), [(0x33711ec, 0x33747bc)])
    assert len(c.edges) == 428 and len(c.secondary) == 8
    c.run(0x312aa08, (MANAGER,), [(0x312aa08, 0x312aa80)])
    assert [t['queue'] for t in c.threads] == list(range(40))
    assert [t['argument'] for t in c.threads] == [hex(MANAGER + 0x310 + i * 0x90) for i in range(40)]
    selected = {}
    for seq in (0x1bc, 0xb2, 0x34, 0x4bd, 0x2f, 0x521):
        selected[hex(seq)] = {'name': c.name(seq), 'queue': c.queue(seq),
                              'configured_dependencies': [{'id': hex(dst), 'name': c.name(dst)}
                                                          for src, dst in c.edges if src == seq]}
    assert selected['0x1bc']['name'] == 'sequence_select_lut'
    assert selected['0x1bc']['queue'] == 0 and selected['0x4bd']['queue'] == 2
    # Do not infer absence from a hand-picked subset: capture every insert
    # performed by the native constructor, then inspect all incoming/outgoing.
    lut_edges = [(hex(src), hex(dst)) for src, dst in c.edges if 0x1bc in (src, dst)]
    assert lut_edges == []
    messages = [c.message_name(0x5840a20, 0x403d), c.message_name(0x58410a0, 0x40a5),
                c.message_name(0x5840400, 0x300d)]
    cases = [Worker(raw, manifest, special).execute_worker(system)
             for system in (2, 3) for special in (False, True)]
    report = {'status': 'NATIVE_SCHEDULER_LOCAL_CONTRACT_VERIFIED', 'camera_io': False,
              'readiness': 'NOT_READY_TO_FLASH', 'ap_sha256': sha(raw),
              'source_sha256': {name: sha((HERE / name).read_bytes()) for name in
                                (Path(__file__).name, 'verify_menu.py', 'verify_upload_guards.py', 'verify_lut_upload.py')},
              'selected_sequences': selected, 'configured_dependency_edges': c.edges,
              'secondary_configuration': c.secondary, 'lut_dependency_edges': lut_edges,
              'release_related_message_identity': messages,
              'thread_creation_requests': c.threads, 'worker_cases': cases,
              'boundaries': ['No threads created; native factory calls captured',
                             'Dependency container insertions captured; allocator/map implementations are fixtures',
                             'Worker queue, dependency vector and OS synchronization supplied as fixtures',
                             'Worker executes real LUT task and dependency-wait code with an empty vector',
                             'Upload libc, transfer, message delivery, completion notification and destruction are fixtures'],
              'not_proven': ['No runtime additions to dependencies', 'Complete release-inhibit/model scheduling',
                             'CP capture versus AP transfer serialization', 'No hardware race, pixels or flash readiness']}
    (FOLDER / 'sequence-scheduling-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'selected': selected, 'lut_edges': lut_edges, 'dependency_edges': len(c.edges),
                      'thread_requests': len(c.threads), 'worker_cases': len(cases)}, indent=2))


if __name__ == '__main__': main()
