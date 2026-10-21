"""Execute native PP/LUT model snapshot/default callbacks, not persistent storage."""
import json
import struct
from pathlib import Path

from install_transaction import digest
from verify_menu import Native, RAM

HERE = Path(__file__).resolve().parent
TABLE = 0x571a560
ALLOWED = ((0x2ae0038, 0x2ae00c8), (0x2a77574, 0x2a776a4),
           (0x2abb894, 0x2abb8a4), (0x2c302a0, 0x2c30328),
           (0x2c30658, 0x2c306e0), (0x2c30090, 0x2c30108),
           (0x26a6eec, 0x26a6f64), (0x1b29b00, 0x1b29b34),
           (0x1c00c78, 0x1c00cac))
PROPERTIES = (
    {'name': 'picture_profile', 'id': 0x66d, 'key': 0x02cf0053,
     'active': 0x7e705f0, 'metadata': 0x7e705f8, 'snapshot': 0x8372950,
     'callbacks': (0x2a77648, 0x2a77668, 0x2a77634, 0x2abb894, 0x2c302a0, 0x2a7760c),
     'values': (0, 1, 11, 12, 13, 14, 15, 16),
     'keys_at': (0x4ba9070, 0x4bc39e8, 0x4bd1748, 0x4be7548, 0x57b9474)},
    {'name': 'selected_lut', 'id': 0x66e, 'key': 0x02cf102d,
     'active': 0x7e70620, 'metadata': 0x7e70628, 'snapshot': 0x8372980,
     'callbacks': (0x2a775b0, 0x2a775d0, 0x2a7759c, 0x2abb89c, 0x2c30658, 0x2a77574),
     'values': (0, 2, 3, 7),
     'keys_at': (0x4ba90a8, 0x4bc3a20, 0x4bd1780, 0x4be7580, 0x57b9494)},
)


def main():
    path = HERE / 'dev-menu-02/appFw.so'
    if not path.exists():
        path = HERE / 'dev-menu-02/candidate/appFw.so'
    raw = path.read_bytes()
    n = Native(raw)
    records = []
    for prop in PROPERTIES:
        mid, active, meta, snap = (prop[k] for k in ('id', 'active', 'metadata', 'snapshot'))
        callbacks = tuple(n.qword(TABLE + mid * 48 + i * 8) for i in range(6))
        assert callbacks == prop['callbacks']
        for at in prop['keys_at']:
            assert struct.unpack_from('<I', raw, at)[0] == prop['key']
        for value in prop['values']:
            n.write(meta, bytes(40))
            # Execute the real row's initialization callback; it binds the
            # metadata-backed value to itself, as seen in the native boot loop.
            n.run(callbacks[5], allowed=ALLOWED)
            assert n.qword(meta + 8) == meta
            n.put(active, 0x11111111)
            n.put(meta, 0x22222222)
            n.put(RAM + 0x8000, value)
            # This dispatcher is called by default-value initialization.
            # It is NOT proof that disk reload uses the same function.
            n.run(0x2ae00a8, (mid, RAM + 0x8000), ALLOWED)
            assert n.word(active) == n.word(meta) == n.word(meta + 0x10) == value
            assert n.run(0x2ae0070, (mid,), ALLOWED) == meta
            assert n.run(0x2ae008c, (mid,), ALLOWED) == 4
            # Snapshot reads the metadata-backed value, not the active value.
            n.put(active, 0x33333333)
            n.run(0x2ae0038, (mid,), ALLOWED)
            assert n.word(snap) == value
            n.put(active, 0x44444444)
            n.put(meta, 0x55555555)
            n.run(0x2ae0054, (mid,), ALLOWED)
            assert n.word(active) == n.word(meta) == value
            assert n.qword(meta + 8) == meta
            records.append({'model_id': mid, 'value': value, 'active_and_metadata_restored': True})
    report = {
        'status': 'MODEL_CALLBACKS_VERIFIED_STORAGE_AND_MODE_SWITCH_UNVERIFIED',
        'camera_io': False, 'candidate_flash_ready': False,
        'ap_sha256': digest(raw),
        'sources': {name: digest((HERE / name).read_bytes()) for name in
                    ('verify_menu_value_callbacks.py', 'verify_menu.py', 'build.py')},
        'callback_table_va': TABLE, 'properties': PROPERTIES, 'cases': records,
        'verified': ['Actual table-dispatched callbacks and model getters',
                     'Initialization pointer, default-value application and metadata copy',
                     'Snapshot/restore preserve PPLUT values 12 through 15 without local clamping',
                     'Stack and callee-saved registers preserved on all executed returns'],
        'fixtures': ['Framework write locks, tracing and model notification dispatch',
                     'Input values, model initialization and chosen callback invocation order'],
        'not_verified': ['Nonvolatile storage write/read or key-to-model runtime conversion',
                         'Still/movie selection bank and complete event loop',
                         'Linked PPLUT1-4 slots, import/delete/upload',
                         'Cold start, MR recall, actual LUT data or JPEG']}
    (HERE / 'dev-menu-02/menu-value-callback-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'camera_io': False, 'cases': len(records)}, indent=2))


if __name__ == '__main__':
    main()
