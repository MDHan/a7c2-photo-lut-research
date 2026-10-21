"""Reviewed dependency order for pinned dev-menu-02 and dev-menu-03 pairs.

This removes branch-to-unwritten-body window boundaries. It is NOT a live-patch
protocol: pwrite atomicity, instruction caches, active PCs and AP/CP activation
still require a separately established camera execution/quiescence protocol.
"""
from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from install_transaction import PROGRAMS, require

PINNED = {'appFw.so': 'a3bffb09002988c4873122b6db41a2e23c87c2a66ff82a2d53b0fdb6959f533d',
          'cpapp-b.bin': '48ff01e346ac74e78b61f811725c0bd95ab2712938b55ad607a5b2f54a3bf4e1'}
PINNED_03 = {**PINNED, 'appFw.so': '5e0741cf58f4125f7b6f5950b5d13d47be025052c9dcc1a799e2ce004cd32c93'}
UPLOAD_ENTRIES = ((0, 0x34285fc), (0, 0x3021184))
AP_BODY, CP_BODY = (0, 0x51a6d00), (1, 0xb27490)
AP_HEADERS = ((0, 0x60), (0, 0x68))
CP_HEADER = (1, 0x20128)
AP_ENTRIES = ((0, 0x303de48), (0, 0x352c5dc))
CP_ENTRY, CP_GUARD = (1, 0x384740), (1, 0x384744)
CONSUMERS = {AP_ENTRIES[0]: AP_BODY, AP_ENTRIES[1]: AP_BODY,
             CP_ENTRY: CP_BODY, CP_GUARD: CP_BODY}


def consumers_for(package):
    pair = package.expected('candidate')
    require(pair in (PINNED, PINNED_03), 'No reviewed native write order for this firmware pair')
    extra = UPLOAD_ENTRIES if pair == PINNED_03 else ()
    return {**CONSUMERS, **{entry: AP_BODY for entry in extra}}


def install_order(package, windows):
    # Byte-array unit fixtures are not executable firmware images. Any real
    # ELF candidate needs an explicit reviewed policy, never a silent fallback.
    if not package.files[PROGRAMS[0]]['candidate'].startswith(b'\x7fELF'):
        return list(windows), []
    consumers = consumers_for(package)
    ap_entries = tuple(entry for entry in consumers if entry[0] == 0)
    by_key = {(f, at): (f, at, size) for f, at, size in windows}
    expected = {AP_BODY, CP_BODY, *AP_HEADERS, CP_HEADER, *ap_entries, CP_ENTRY, CP_GUARD,
                (0, 0xa3bc8), (0, 0x5235de8), (0, 0x5235df8), (0, 0x5235e00),
                (0, 0x5235e08), (0, 0x5235e18), (0, 0x59a2b74), (0, 0x59a2c2c),
                (0, 0x59a2ce4), (0, 0x59a2d9c)}
    require(set(by_key) == expected and len(windows) == len(expected), 'Native order window set changed')
    for consumer, body in consumers.items():
        file, at = consumer
        raw = package.files[PROGRAMS[file]]['candidate']
        delta = 0 if file == 0 else 0x108000
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN) if file == 0 else Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        ins = next(decoder.disasm(raw[at:at+4], at+delta), None)
        require(ins is not None and ins.mnemonic in ('b', 'bl', 'b.w'), 'Expected native entry branch missing')
        target = int(ins.op_str.lstrip('#'), 16) - delta
        require(body[1] <= target < body[1] + by_key[body][2], 'Native entry targets another body')
    edges = set()
    for header in AP_HEADERS: edges.add((AP_BODY, header))
    edges.add((CP_BODY, CP_HEADER))
    for prerequisite in (CP_BODY, CP_HEADER): edges.add((prerequisite, CP_GUARD))
    edges.add((CP_GUARD, CP_ENTRY))
    for entry in ap_entries:
        for prerequisite in (AP_BODY, *AP_HEADERS, CP_ENTRY): edges.add((prerequisite, entry))
    structural = {AP_BODY, CP_BODY, *AP_HEADERS, CP_HEADER, *ap_entries, CP_ENTRY, CP_GUARD}
    for data in expected - structural:
        for entry in ap_entries: edges.add((entry, data))
    pending, ordered = set(expected), []
    while pending:
        ready = sorted(node for node in pending if not any(dst == node and src in pending for src, dst in edges))
        require(bool(ready), 'Cycle in native write dependencies')
        node = ready[0]
        ordered.append(by_key[node])
        pending.remove(node)
    return ordered, sorted(edges)
