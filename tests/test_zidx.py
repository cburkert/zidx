import unittest
import secrets

import zidx


class TestZIDX(unittest.TestCase):
    def setUp(self):
        key = secrets.token_bytes(32)
        self.client = zidx.Client(5, 0.001, key)
        self.idx = self.client.buildIndex("foo", ["dog", "cat"])

    def test_contain(self):
        trap = self.client.trapdoor("dog")
        self.assertTrue(self.idx.search(trap))
        self.assertTrue(trap in self.idx)

    def test_not_contain(self):
        trap = self.client.trapdoor("mouse")
        self.assertTrue(self.idx.search(trap) is False)
        self.assertTrue(trap not in self.idx)

    def test_partial(self):
        trap = self.client.partial_trapdoor("dog")
        self.assertTrue(trap in self.idx)

    def test_keynum_mismatch(self):
        self.assertRaises(ValueError,
                          zidx.Client, 5, 0.001, key=(b"deadbeef",))

    def test_create_from_bitstring(self):
        idx2 = zidx.Index("foo", bitstring=self.idx.to_bitstring())
        self.assertEqual(self.idx, idx2)
        trap_dog = self.client.trapdoor("dog")
        self.assertTrue(trap_dog in idx2)
        trap_mouse = self.client.trapdoor("mouse")
        self.assertTrue(trap_mouse not in idx2)

    def test_key_derivation(self):
        k1 = self.client._derive_keys(b"deadbeef")
        k2 = self.client._derive_keys(b"deadbeef")
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), self.client.num_keys)
        self.assertEqual(len(k1), len(set(k1)))
        for subkey in k1:
            self.assertEqual(len(subkey), zidx.zidx.HASHLEN_BITS // 8)

    def test_trapdoor_serializer(self):
        trap = self.client.trapdoor("dog")
        hexcsv = trap.toHexCSV()
        self.assertEqual(trap, zidx.Trapdoor.fromHexCSV(hexcsv))


if __name__ == '__main__':
    unittest.main()
