"""Execute original PP rule evaluation and inhibition updates for dev-menu-02.

Input parameter states are fixtures, not a camera snapshot. PP computation,
reference counts, model-byte writes, and option callbacks execute native code.
Other parameters' inhibition notifications and the final event queue are
explicit boundaries; this is not a full camera event-loop test.
"""
import argparse
import itertools
import json
import struct
from pathlib import Path
from datetime import datetime, timezone

import build as b
from verify_menu import Native, RAM, STACK, STOP, X, OPTIONS, a

PP, EXPOSURE, DIRECT = 0x3f5, 0x14d, 0x11e
STATES, COUNTERS = 0x7e340d0, 0x7e18d28
MANAGER, ACCESSOR, BUCKET = RAM + 0x7000, RAM + 0x7100, RAM + 0x7200
ROW, VALUE, PRIORITY = RAM + 0x6000, RAM + 0x6100, RAM + 0x6200
ALLOWED = ((0x247154c, 0x247192c), (0x246e814, 0x246ea2c),
           (0x246f158, 0x246f6ac), (0x2506808, 0x250692c),
           (0x2506aa8, 0x2506b9c), (0x24cc09c, 0x24cc104),
           (0x28bb17c, 0x28bb274), (0x2490e18, 0x2490e9c),
           (0x1bb9718, 0x1bb97f8), (0x2470f14, 0x2471068),
           (0x2506054, 0x25060f4), (0x2506220, 0x2506508),
           (0x28bb0c8, 0x28bb140), (0x2775e98, 0x2775ec8))


class Engine(Native):
    def __init__(self, raw):
        super().__init__(raw)
        self.skipped_non_pp = 0
        self.queue_calls = 0
        self.table = self.qword(0x5b66c10)
        self.ranges = self.qword(0x5b874a8)
        records = self.qword(self.table + PP * 16)
        self.sources = [self.word(self.qword(records + i * 8) + 12)
                        for i in range(self.word(self.table + PP * 16 + 8))]
        assert len(self.sources) == 19 and len(set(self.sources)) == 19
        for source in self.sources:
            self.put(STATES + source * 24, source)
            self.put(STATES + source * 24 + 8, 0x80000000)
        self.write(MANAGER, struct.pack('<Q', ACCESSOR))
        self.write(ACCESSOR, struct.pack('<Q', 0x5b2c088))
        # Empty alias registry and subscriber vectors. Native hash lookup is
        # still executed, but alias propagation itself is outside this test.
        registry = self.qword(0x5bb24b8)
        self.write(registry, struct.pack('<QQ', BUCKET, 1))
        self.write(BUCKET, bytes(8))
        self.write(0x7e4e740, bytes(24))
        self.write(0x7e4e6c0, bytes(24))
        self.write(0x7e4e608, bytes(1))
        self.write(0x7e4e5e8, bytes(1))
        self.write(self.run(0x2862698), bytes(1))
        self.metadata = self.run(0x28696b0)
        self.write(self.metadata + 0x15, bytes(16))
        for value in range(0x3115, 0x3126):
            self.put(COUNTERS + value * 4, 0)

    def code(self, u, address, size, data):
        if address == 0x246f404 and u.reg_read(X(1)) != PP:
            self.skipped_non_pp += 1
            self.ret()
            return
        if address == 0x2f3b170:
            self.queue_calls += 1
            self.events.append('fixture: final model notification queue')
            self.ret()
            return
        if address in (0x1794224, 0x1794280, 0x3682148, 0x2e017c4, 0x2d8dd84, 0x2e0af7c):
            self.events.append('fixture: lock/log/subscriber boundary ' + hex(address))
            self.ret()
            return
        super().code(u, address, size, data)

    def execute(self, entry, args):
        self.allowed = list(ALLOWED) + [(0x2850000, 0x28a0000)]
        self.events = []
        for i, value in enumerate(args):
            self.u.reg_write(X(i), value)
        preserved = {X(i): 0x22220000 + i for i in range(19, 30)}
        for reg, value in preserved.items():
            self.u.reg_write(reg, value)
        self.u.reg_write(a.UC_ARM64_REG_SP, STACK + 0xff00)
        self.u.reg_write(a.UC_ARM64_REG_LR, STOP)
        self.ensure(entry, 4)
        self.u.emu_start(entry, STOP, count=1000000)
        assert self.u.reg_read(a.UC_ARM64_REG_PC) == STOP, hex(self.u.reg_read(a.UC_ARM64_REG_PC))
        assert self.u.reg_read(a.UC_ARM64_REG_SP) == STACK + 0xff00
        assert all(self.u.reg_read(reg) == value for reg, value in preserved.items())

    def evaluate(self, exposure, value, extra=None):
        for source in self.sources:
            self.put(STATES + source * 24 + 8, 0x80000000)
        self.put(STATES + EXPOSURE * 24 + 8, exposure)
        for source, state in (extra or {}).items():
            assert source in self.sources
            self.put(STATES + source * 24 + 8, state)
        self.write(ROW, struct.pack('<6I', PP, value, value, value, 0, 0))
        self.put(VALUE, value)
        self.put(PRIORITY, 0)
        self.execute(0x247154c, (MANAGER, ROW, VALUE, PRIORITY, 0))
        assert not self.events, self.events
        return self.word(VALUE)

    def update(self, source, value, add):
        self.put(RAM + 0x6300, source)
        self.put(RAM + 0x6400, value)
        self.execute(0x246f54c, (MANAGER, RAM + 0x6300, RAM + 0x6400, int(add)))

    def publish(self, value):
        self.put(ROW + 8, value)
        self.execute(0x2470f14, (MANAGER, ROW, 0))
        ptr = self.run(0x286969c)
        assert self.word(ptr) == value - 0x3115
        return self.word(ptr)

    def flags(self):
        values = []
        for profile in range(12, 16):
            callback = self.qword(OPTIONS + profile * 0xb8 + 0x98)
            self.execute(callback, ())
            flag = self.u.reg_read(X(0))
            counter = self.word(COUNTERS + (0x3115 + profile) * 4)
            assert flag == int(counter != 0), (profile, flag, counter)
            values.append({'profile': profile, 'inhibit_count': counter, 'callback_byte': flag})
        return values


def main(folder):
    raw = (folder / 'candidate/appFw.so').read_bytes()
    baseline = (b.HERE / 'dev-menu-01/candidate/appFw.so').read_bytes()
    old, new = Engine(baseline), Engine(raw)
    changed, unchanged = 0, 0
    # All exposure modes and every PP value; only PPLUT in P/A/S/M changes.
    lo, hi = (old.word(old.ranges + EXPOSURE * 12 + i) for i in (0, 4))
    for exposure, value in itertools.product(range(lo, hi + 1), range(0x3115, 0x3126)):
        before, after = old.evaluate(exposure, value), new.evaluate(exposure, value)
        if exposure in range(0x172c, 0x1730) and value in range(0x3121, 0x3125):
            assert before == 0x3115 and after == value
            changed += 1
        else:
            assert before == after, (hex(exposure), hex(value), before, after)
            unchanged += 1
    # Every other incoming rule, each of its values: test independently with
    # the exposure input absent (native UNKNOWN), then with new still PASM.
    # No exhaustive simultaneous 19-way combination is claimed.
    other_cases = 0
    for source in old.sources:
        if source == EXPOSURE:
            continue
        lo, hi = (old.word(old.ranges + source * 12 + i) for i in (0, 4))
        assert old.word(old.ranges + source * 12 + 8) & 255 == 0
        for source_value, value in itertools.product(range(lo, hi + 1), range(0x3121, 0x3125)):
            before = old.evaluate(0x80000000, value, {source: source_value})
            for exposure in range(0x172c, 0x1730):
                after = new.evaluate(exposure, value, {source: source_value})
                assert before == after, (hex(source), hex(source_value), hex(value), hex(exposure), before, after)
                other_cases += 1
    transitions = []
    for exposure in range(0x172c, 0x1730):
        for label, engine in (('before', old), ('after', new)):
            engine.update(EXPOSURE, exposure, True)
            first = engine.flags()
            assert all(r['inhibit_count'] == int(label == 'before') for r in first)
            engine.update(DIRECT, 0x15d2, True)
            second = engine.flags()
            assert all(r['inhibit_count'] == 1 + int(label == 'before') for r in second)
            engine.update(EXPOSURE, exposure, False)
            third = engine.flags()
            assert all(r['inhibit_count'] == 1 for r in third)
            engine.update(DIRECT, 0x15d2, False)
            fourth = engine.flags()
            assert all(r['inhibit_count'] == 0 for r in fourth)
            transitions.append({'mode': hex(exposure), 'image': label,
                                'exposure': first, 'plus_direct_rec': second,
                                'remove_exposure': third, 'remove_direct_rec': fourth})
    menu_chain = []
    for label, engine in (('before', old), ('after', new)):
        for exposure, profile in itertools.product(range(0x172c, 0x1730), range(12, 16)):
            # Initialize the non-PP model fields through the existing fixture,
            # then execute menu commit and rule evaluation before rebuilding
            # the task WITHOUT reinitializing the model selection.
            engine.task(0x311a88c, 2, profile, 3, 1)
            engine.menu_commit(profile)
            evaluated = engine.evaluate(exposure, 0x3115 + profile)
            actual = engine.publish(evaluated)
            assert actual == (0 if label == 'before' else profile)
            engine.write(RAM + 0x4000, b'\xa5' * 0x80)
            engine.run(0x311a88c, (RAM + 0x4000,),
                       ((0x311a63c, 0x311aaac), (0x303dca0, 0x303de98),
                        (0x3105ce0, 0x3105dac), (0x51a6d3c, 0x51a6d70)))
            message = engine.send_base_task()
            if label == 'after':
                assert message == [10, 0, 0, 1, 0], message
            menu_chain.append({'image': label, 'exposure': hex(exposure), 'selected_profile': profile,
                               'profile_after_native_exclusion_writeback': actual, 'message': message})
    report = {'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'camera_io': False,
              'candidate_sha256': b.sha(raw), 'baseline_sha256': b.sha(baseline),
              'target_evaluator_changes': changed, 'unaffected_evaluator_cases': unchanged,
              'other_constraint_comparisons': other_cases, 'native_inhibition_transitions': transitions,
              'menu_to_native_exclusion_writeback_to_task_message': menu_chain,
              'full_event_loop_verified': False, 'persistence_verified': False,
              'fixtures': ['Input exclusion states', 'Empty alias registry and subscribers',
                           'Non-PP inhibition updates intercepted', 'Model locks and final queue boundary',
                           'Subscriber propagation disabled in fixture', 'Setting message transport captured'],
              'native_executed': ['All 19 incoming PP rules', 'Original source-to-rule selector',
                                  'PP inhibition reference counting', 'Native enum-to-model translation',
                                  'Actual per-value model byte writes', 'Original PPLUT option callbacks',
                                  'Menu confirmation', 'Exclusion value writeback through actual model setter',
                                  'Task construction after native writeback and original AP sender'],
              'source_sha256': b.sha(Path(__file__).read_bytes())}
    (folder / 'dynamic-menu-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('target_evaluator_changes', 'unaffected_evaluator_cases',
                                           'other_constraint_comparisons', 'full_event_loop_verified')}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    main(parser.parse_args().folder)
