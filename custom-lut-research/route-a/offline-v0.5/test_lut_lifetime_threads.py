"""Host-native concurrent callers for the same freestanding lifecycle core."""
import ctypes as c
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import threading

HERE = Path(__file__).resolve().parent
OUT = HERE/'lifecycle-dev'


class Cell(c.Structure):
    _fields_ = [('word', c.c_uint32)]


def main():
    libpath = OUT/'photo_lut_lifetime.dylib'
    cmd = ['/usr/bin/clang', '-dynamiclib', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
           str(HERE/'photo_lut_lifetime.c'), '-o', str(libpath)]
    subprocess.run(cmd, check=True, capture_output=True)
    lib = c.CDLL(str(libpath))  # CDLL releases the GIL while executing C.
    arity = {'pll_begin': 1, 'pll_load_complete': 2, 'pll_submit_complete': 2,
             'pll_vfx_complete': 3, 'pll_fault': 1, 'pll_take_release': 1,
             'pll_release_complete': 2}
    for name, n in arity.items():
        fn = getattr(lib, name)
        fn.argtypes = [c.POINTER(Cell)] + [c.c_uint32]*n
        fn.restype = c.c_uint32
    cell = Cell(0x80)
    ptr = c.byref(cell)
    previous = None
    with ThreadPoolExecutor(max_workers=8) as pool:
        def together(calls):
            barrier = threading.Barrier(len(calls))
            def run(call):
                barrier.wait(timeout=10)
                name, args = call
                return getattr(lib, name)(ptr, *args)
            return list(pool.map(run, calls))
        rounds = []
        for epoch in range(1, 65):
            # Contending submitters cannot both acquire the same free context.
            starts = together([('pll_begin', (15,))]*8)
            tags = [t for t in starts if t]
            assert tags == [(epoch << 8) | 2]
            tag = tags[0]
            events = [('pll_load_complete', (tag, 1)), ('pll_submit_complete', (tag, 1))]
            events += [('pll_vfx_complete', (tag, ch, 0)) for ch in range(3, 6)]
            if previous is not None:
                # Old success/error events race new valid events. They must
                # neither clear missing channel 6 nor fault the new epoch.
                events += [('pll_vfx_complete', (previous, 6, 0)),
                           ('pll_fault', (previous,)), ('pll_load_complete', (previous, 0))]
            results = together(events)
            assert results[:5] == [1]*5 and all(x == 0 for x in results[5:])
            assert cell.word == (epoch << 8) | 8
            assert lib.pll_take_release(ptr, tag) == 0
            assert lib.pll_vfx_complete(ptr, tag, 6, 0) == 1
            claims = together([('pll_take_release', (tag,))]*8)
            assert sum(claims) == 1
            assert lib.pll_release_complete(ptr, tag, 1) == 1
            assert cell.word == (epoch << 8) | 0x80
            rounds.append({'epoch': epoch, 'one_begin_winner': True,
                           'one_release_winner': True, 'no_lost_completion': True,
                           'stale_events_rejected': previous is not None})
            previous = tag
    report = {'status': 'COMPONENT_TEST_ONLY', 'camera_io': False,
              'rounds': rounds, 'compiler_command': cmd,
              'source_sha256': hashlib.sha256((HERE/'photo_lut_lifetime.c').read_bytes()).hexdigest(),
              'test_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'library_sha256': hashlib.sha256(libpath.read_bytes()).hexdigest(),
              'limitations': ['host concurrency is not the CP interrupt scheduler',
                              'does not validate production state placement or native resource ownership']}
    (OUT/'thread-verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'concurrent_epochs': len(rounds), 'status': report['status']}))


if __name__ == '__main__': main()
