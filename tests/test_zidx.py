import unittest

import zidx


class TestZIDX(unittest.TestCase):
    def setUp(self):
        self.client = zidx.Client(5, 0.001)
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
                          zidx.Client, 5, 0.001, keys=(b"deadbeef",))


if __name__ == '__main__':
    unittest.main()
