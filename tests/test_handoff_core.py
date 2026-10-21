"""Real original C state machines on the host; no firmware, pixels or hardware."""
import ctypes as C
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest

SRC = Path(__file__).resolve().parents[1] / 'custom-lut-research/route-a/offline-v0.5'
U = C.c_uint32
BYTE = C.c_ubyte
class AP(C.Structure):
    _fields_ = [('control', U), ('session_lo', U), ('session_hi', U), ('generation', U)]
class CP(C.Structure):
    _fields_ = [(n, U) for n in ('lock', 'gate', 'initialized', 'session_lo', 'session_hi', 'last_id', 'phase', 'generation')] + [('readers', U * 29)]
class Cell(C.Structure):
    _fields_ = [('word', U)]

def compile_library(destination, sources):
    compiler = shutil.which('cc')
    if not compiler:
        raise RuntimeError('A C compiler is required for these tests')
    mode = '-dynamiclib' if platform.system() == 'Darwin' else '-shared'
    subprocess.run([compiler, '-std=c11', '-O2', '-fPIC', mode, *[str(SRC / s) for s in sources], '-o', str(destination)], check=True, capture_output=True)
    return C.CDLL(str(destination))

def function(lib, name, *args):
    fn = getattr(lib, name)
    fn.argtypes = list(args)
    fn.restype = U
    return fn

class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='photo-lut-host-')
        cls.lib = compile_library(Path(cls.tmp.name) / 'handoff.so', ['lut_handoff_ap.c', 'lut_handoff_cp.c'])
        A, P, B = C.POINTER(AP), C.POINTER(CP), C.POINTER(BYTE)
        for name, args in {
            'lh_ap_open': (A,U,U), 'lh_ap_begin': (A,), 'lh_ap_write': (A,U),
            'lh_ap_written': (A,U,U), 'lh_ap_cancel': (A,U), 'lh_ap_request': (A,B),
            'lh_ap_receive': (A,B,U), 'lh_cp_open': (P,U,U,U),
            'lh_cp_reader_begin': (P,), 'lh_cp_reader_end': (P,U), 'lh_cp_reader_fault': (P,U),
            'lh_cp_request': (P,B,U,B), 'lh_cp_published': (P,U,U,U,B),
        }.items():
            function(cls.lib, name, *args)
    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
    def setUp(self):
        self.ap, self.cp = AP(), CP()
        self.assertEqual(self.lib.lh_ap_open(C.byref(self.ap), 0x1234, 0x5678), 1)
        self.assertEqual(self.lib.lh_cp_open(C.byref(self.cp), 0x1234, 0x5678, 17), 1)
    def phase(self):
        return self.ap.control & 15
    def request(self):
        packet = (BYTE * 32)()
        self.assertEqual(self.lib.lh_ap_request(C.byref(self.ap), packet), 32)
        return packet
    def deliver(self, packet=None, receive=True):
        if packet is None:
            packet = self.request()
        reply = (BYTE * 32)()
        result = self.lib.lh_cp_request(C.byref(self.cp), packet, len(packet), reply)
        if result == 2 and receive:
            self.lib.lh_ap_receive(C.byref(self.ap), reply, 32)
        return result, bytes(reply)
    def begin_write(self):
        id = self.lib.lh_ap_begin(C.byref(self.ap))
        self.assertNotEqual(id, 0)
        self.assertEqual(self.deliver()[1][15], 0)
        self.assertEqual(self.lib.lh_ap_write(C.byref(self.ap), id), 1)
        return id
    def test_writer_waits_for_reader_and_publication(self):
        token = self.lib.lh_cp_reader_begin(C.byref(self.cp))
        id = self.lib.lh_ap_begin(C.byref(self.ap))
        self.assertEqual(self.deliver()[1][15], 1)
        self.assertEqual(self.lib.lh_ap_write(C.byref(self.ap), id), 0)
        self.assertEqual(self.lib.lh_cp_reader_end(C.byref(self.cp), token), 1)
        self.assertEqual(self.deliver()[1][15], 0)
        self.assertEqual(self.lib.lh_ap_write(C.byref(self.ap), id), 1)
        self.assertEqual(self.lib.lh_ap_cancel(C.byref(self.ap), id), 0)
        self.assertEqual(self.lib.lh_ap_written(C.byref(self.ap), id, 1), 1)
        self.assertEqual(self.deliver()[0], 3)
        # Explicit native-publication fixture boundary, not a pixel operation.
        reply = (BYTE * 32)()
        self.assertEqual(self.lib.lh_cp_published(C.byref(self.cp), id, 1, 18, reply), 2)
        self.lib.lh_ap_receive(C.byref(self.ap), reply, 32)
        self.assertEqual(self.phase(), 1)
        self.assertEqual(self.cp.gate, 0)
        self.assertEqual(self.cp.generation, 18)
        self.assertEqual(self.lib.lh_cp_reader_end(C.byref(self.cp), token), 0)
    def test_cancelled_grant_cannot_start_copy(self):
        id = self.lib.lh_ap_begin(C.byref(self.ap))
        _, reply = self.deliver(receive=False)
        self.assertEqual(self.lib.lh_ap_cancel(C.byref(self.ap), id), 1)
        late = (BYTE * 32).from_buffer_copy(reply)
        self.lib.lh_ap_receive(C.byref(self.ap), late, 32)
        self.assertEqual(self.phase(), 7)
        self.assertEqual(self.lib.lh_ap_write(C.byref(self.ap), id), 0)
        self.assertEqual(self.deliver()[1][15], 0)
        self.assertEqual(self.phase(), 1)
        self.assertEqual(self.lib.lh_cp_reader_begin(C.byref(self.cp)), 0)
    def test_failed_copy_does_not_reopen_invalid_buffer(self):
        id = self.begin_write()
        self.assertEqual(self.lib.lh_ap_written(C.byref(self.ap), id, 0), 1)
        self.assertEqual(self.deliver()[1][15], 0)
        self.assertEqual(self.phase(), 1)
        self.assertNotEqual(self.cp.gate & 0x40000000, 0)
        self.assertEqual(self.lib.lh_cp_reader_begin(C.byref(self.cp)), 0)
        self.assertGreater(self.begin_write(), id)
    def test_dma_fault_retains_lease(self):
        token = self.lib.lh_cp_reader_begin(C.byref(self.cp))
        self.assertEqual(self.lib.lh_cp_reader_fault(C.byref(self.cp), token), 1)
        self.assertEqual(self.lib.lh_cp_reader_end(C.byref(self.cp), token), 0)
        self.assertNotEqual(self.cp.gate & 0x20000000, 0)
        self.assertNotEqual(self.cp.gate & 0x1fffffff, 0)
        self.assertEqual(self.lib.lh_cp_reader_begin(C.byref(self.cp)), 0)
    def test_session_reopen_preserves_reader(self):
        token = self.lib.lh_cp_reader_begin(C.byref(self.cp))
        before = bytes(self.cp)
        self.assertEqual(self.lib.lh_cp_open(C.byref(self.cp), 0x9999, 0x8888, 0), 0)
        self.assertEqual(bytes(self.cp), before)
        self.assertEqual(self.lib.lh_cp_reader_end(C.byref(self.cp), token), 1)
    def test_short_or_wrong_session_reply_cannot_grant(self):
        self.lib.lh_ap_begin(C.byref(self.ap))
        _, reply = self.deliver(receive=False)
        for mode in ('short', 'identity', 'id'):
            bad = bytearray(reply)
            if mode == 'identity':
                bad[16] ^= 1
            elif mode == 'id':
                bad[4] ^= 1
            packet = (BYTE * 32).from_buffer_copy(bad)
            self.lib.lh_ap_receive(C.byref(self.ap), packet, 31 if mode == 'short' else 32)
            self.assertEqual(self.phase(), 2)
    def test_cancel_tombstone_rejects_late_acquire(self):
        id = self.lib.lh_ap_begin(C.byref(self.ap))
        acquire = self.request()
        self.assertEqual(self.lib.lh_ap_cancel(C.byref(self.ap), id), 1)
        self.assertEqual(self.deliver()[1][15], 0)
        self.assertEqual(self.deliver(acquire, receive=False)[1][15], 2)

class PhotoCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='photo-completion-host-')
        cls.lib = compile_library(Path(cls.tmp.name) / 'completion.so', ['photo_lut_completion.c'])
        P = C.POINTER(Cell)
        for name, args in {'pll_begin':(P,U), 'pll_load_complete':(P,U,U), 'pll_submit_complete':(P,U,U), 'pll_fault':(P,U), 'pll_callback_claim':(P,U,U), 'pll_callback_finish':(P,U,U,U)}.items():
            function(cls.lib, name, *args)
    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
    def test_old_callback_cannot_complete_next_photo(self):
        cell = Cell(0x80)
        first = self.lib.pll_begin(C.byref(cell), 1)
        self.assertNotEqual(first, 0)
        self.lib.pll_load_complete(C.byref(cell), first, 1)
        self.lib.pll_submit_complete(C.byref(cell), first, 1)
        self.assertEqual(self.lib.pll_callback_claim(C.byref(cell), first, 3), 1)
        self.assertEqual(self.lib.pll_callback_finish(C.byref(cell), first, 3, 0), 1)
        second = self.lib.pll_begin(C.byref(cell), 1)
        self.assertNotEqual(second, first)
        before = cell.word
        self.assertEqual(self.lib.pll_callback_claim(C.byref(cell), first, 3), 0)
        self.assertEqual(self.lib.pll_callback_finish(C.byref(cell), first, 3, 0), 0)
        self.assertEqual(cell.word, before)
    def test_notification_failure_stays_faulted(self):
        cell = Cell(0x80)
        tag = self.lib.pll_begin(C.byref(cell), 1)
        self.assertEqual(self.lib.pll_callback_claim(C.byref(cell), tag, 3), 1)
        self.assertEqual(self.lib.pll_callback_finish(C.byref(cell), tag, 3, 1), 1)
        self.assertNotEqual(cell.word & 0x40, 0)
        self.assertEqual(self.lib.pll_begin(C.byref(cell), 1), 0)

if __name__ == '__main__':
    unittest.main()
