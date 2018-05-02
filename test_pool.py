import unittest

import demodhcpd


class AddressPoolTest(unittest.TestCase):
    def test_pool(self):
        pool = demodhcpd.AddressPool(['a', 'b', 'c', 'd'])
        self.assertEqual(pool.get_addr('mac1'), 'a')
        self.assertEqual(pool.get_addr('mac2'), 'a')
        assert pool.assign('a', 'mac1', 'hostname1')
        assert pool.assign('a', 'mac1', 'hostname1')
        assert pool.assign('a', 'mac1', 'hostname2')
        assert not pool.assign('a', 'mac2', 'hostname3')
        self.assertEqual(pool.get_addr('mac1'), 'a')
        self.assertEqual(pool.get_addr('mac2'), 'b')
        self.assertEqual(pool.get_addr('mac2'), 'b')
        assert pool.assign('b', 'mac2', 'hostname1')
        assert pool.assign('b', 'mac2', 'hostname1')
        assert not pool.assign('b', 'mac3', 'hostname1')

        assert not pool.assign('x', 'mac4', 'hostname4')

    def test_pool_exhausted(self):
        pool = demodhcpd.AddressPool(['a', 'b'])
        self.assertEqual(pool.get_addr('mac1'), 'a')
        assert pool.assign('a', 'mac1', 'hostname1')
        self.assertEqual(pool.get_addr('mac1'), 'a')
        self.assertEqual(pool.get_addr('mac2'), 'b')
        assert pool.assign('b', 'mac2', 'hostname2')

        self.assertEqual(pool.get_addr('mac1'), 'a')
        self.assertEqual(pool.get_addr('mac2'), 'b')
        self.assertRaises(demodhcpd.NoAddressAvailable, pool.get_addr, 'mac3')

        pool = demodhcpd.AddressPool([])
        self.assertRaises(demodhcpd.NoAddressAvailable, pool.get_addr, 'any')
