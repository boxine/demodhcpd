import unittest

import demodhcpd


class AddressPoolTest(unittest.TestCase):
    def test_pool(self):
        pool = demodhcpd.AddressPool(['a', 'b', 'c', 'd'])
        self.assertEqual(pool.get_addr(), 'a')
        self.assertEqual(pool.get_addr(), 'a')
        assert pool.assign('a', 'mac1', 'hostname1')
        assert pool.assign('a', 'mac1', 'hostname1')
        assert pool.assign('a', 'mac1', 'hostname2')
        assert not pool.assign('a', 'mac2', 'hostname3')
        self.assertEqual(pool.get_addr(), 'b')
        self.assertEqual(pool.get_addr(), 'b')
        assert pool.assign('b', 'mac2', 'hostname1')
        assert pool.assign('b', 'mac2', 'hostname1')
        assert not pool.assign('b', 'mac3', 'hostname1')

        assert not pool.assign('x', 'mac4', 'hostname4')
