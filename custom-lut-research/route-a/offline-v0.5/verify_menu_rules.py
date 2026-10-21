"""Execute the native exclusion-rule selector, without a camera or rule patch.

This checks table selection only. It does not execute the full exclusion
manager, event dispatch, or persistence and cannot establish flash readiness.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import build as b
from verify_menu import Native, RAM


def inspect(raw):
    n = Native(raw)
    ranges = n.qword(0x5b874a8)
    rows = []
    for record, source, expected_range in (
        (0x555ce60, 0x6c, (0x1246, 0x124c)),
        (0x5570890, 0x3f5, (0x3115, 0x3125)),
    ):
        # Native 0x246e814 reads source at +0xc and the pointer at +0.
        assert n.word(record + 8) == 0x3f6
        assert n.word(record + 12) == source
        lo, hi = (n.word(ranges + source * 12 + offset) for offset in (0, 4))
        assert (lo, hi) == expected_range
        assert n.word(ranges + source * 12 + 8) & 255 == 0
        for value in range(lo, hi + 1):
            n.put(RAM + 0x5000, value)
            descriptor = n.run(0x246e814, (record, RAM + 0x5000),
                               ((0x246e814, 0x246ea2c),))
            actions = []
            if descriptor:
                assert n.word(descriptor + 8) == 1
                pointer = n.qword(descriptor)
                actions = [n.word(pointer + i * 4) for i in range(3)]
            if source == 0x6c:
                assert descriptor == (0x525ba50 if value == 0x1249 else 0)
                assert actions == ([0, 0x3127, 0x3128] if value == 0x1249 else [])
            else:
                expected = 0x52a3850 + (value - 0x3121) * 16 if 0x3121 <= value <= 0x3124 else 0
                assert descriptor == expected
                assert actions == ([1, 0x80000000, 0x3127] if expected else [])
            rows.append({'source_parameter': hex(source), 'value': hex(value),
                         'descriptor': hex(descriptor),
                         'action_words': [hex(x) for x in actions]})
    assert n.events == [], 'No framework fixtures expected for the selector'
    return rows


def main():
    folder = b.HERE / 'dev-menu-01'
    baseline = (b.BASE / 'appFw.so').read_bytes()
    candidate = (folder / 'candidate/appFw.so').read_bytes()
    manifest = json.loads((folder / 'manifest.json').read_text())
    assert b.sha(baseline) == b.HASHES['appFw.so']
    assert b.sha(candidate) == manifest['outputs']['appFw.so']['sha256']
    before, after = inspect(baseline), inspect(candidate)
    assert before == after
    report = {
        'checked_at_utc': datetime.now(timezone.utc).isoformat(),
        'camera_io': False, 'candidate_sha256': b.sha(candidate),
        'native_selector_cases': len(before) + len(after),
        'baseline_and_candidate_rules_identical': True,
        'framework_stubs_used': False,
        'system_still_rule_descriptor': 0,
        'system_movie_rule_descriptor': '0x525ba50',
        'full_dynamic_availability_computation_verified': False,
        'scope': 'Native selector and actual ELF tables at link-time addresses; no action evaluation, relocation, model event loop or hardware execution.',
        'candidate_cases': after,
        'source_sha256': b.sha(Path(__file__).read_bytes()),
    }
    (b.HERE / 'preflash-audit/menu-rule-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('native_selector_cases', 'baseline_and_candidate_rules_identical',
                                          'full_dynamic_availability_computation_verified')}, indent=2))


if __name__ == '__main__':
    main()
