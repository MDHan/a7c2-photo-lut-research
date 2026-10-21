import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('public_tree', Path(__file__).resolve().parents[1] / 'tools/check_public_tree.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class PublicTreeTests(unittest.TestCase):
    def test_rejects_binary_candidate_and_identity(self):
        self.assertTrue(module.check_file('candidate/appFw.so', b'\x7fELF\0'))
        self.assertTrue(module.check_file('device.private.json', b'{}'))
        self.assertTrue(module.check_file('evidence/raw.json', b'{"patches": []}'))
    def test_rejects_personal_path(self):
        value = ('/' + 'Users' + '/example/private.bin').encode()
        self.assertTrue(module.check_file('docs/sample.md', value))
    def test_accepts_plain_source(self):
        self.assertEqual(module.check_file('src/example.c', b'int f(void) { return 0; }\n'), [])
