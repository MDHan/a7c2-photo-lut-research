"""Validate the portable native core's fixed binary report, without device I/O."""
import struct

from install_transaction import PROGRAMS, Rejected, require

LAYOUT = struct.Struct('<6I3q32s64s64s')


def decode_receipt(raw, operation_id, expected_before, expected_target):
    require(isinstance(raw, bytes) and len(raw) == LAYOUT.size, 'Invalid native report size')
    (version, outcome, phase, source_verified, writes_started, rollback_verified,
     status, rollback_status, cleanup_status, op, before, after) = LAYOUT.unpack(raw)
    require(version == 1, 'Unsupported native report version')
    require(op.hex() == operation_id, 'Native report operation mismatch')
    require(source_verified in (0, 1) and writes_started in (0, 1) and rollback_verified in (0, 1),
            'Invalid native report flags')
    before = {n: before[i * 32:(i + 1) * 32].hex() for i, n in enumerate(PROGRAMS)}
    after = {n: after[i * 32:(i + 1) * 32].hex() for i, n in enumerate(PROGRAMS)}
    # A native rejection/unknown cleanup does not become a synthetic verified
    # pre-write receipt. The host stops and obtains a separate fresh inspection.
    require(outcome in (1, 2), 'Native operation did not return a verified pair outcome')
    require(source_verified == 1 and writes_started == 1 and cleanup_status == 0,
            'Native source or cleanup is unverified')
    require(before == expected_before, 'Native report source pair mismatch')
    if outcome == 1:
        require((phase, status, rollback_status, rollback_verified) == (8, 0, 0, 0),
                'Inconsistent native written report')
        require(after == expected_target, 'Native report target pair mismatch')
        label = 'written'
    else:
        require(phase == 6 and status < 0 and rollback_status == 0 and rollback_verified == 1,
                'Inconsistent native rollback report')
        require(after == expected_before, 'Native rollback pair mismatch')
        label = 'rolled_back'
    return {'format': 1, 'operation_id': operation_id, 'outcome': label,
            'before_sha256': before, 'after_sha256': after}
