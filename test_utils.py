from __future__ import unicode_literals

import unittest

import demodhcpd

import ipaddress


class UtilsTest(unittest.TestCase):
    def test_iprange(self):
        ipr = list(demodhcpd.ip_range(
            ipaddress.ip_address('10.54.42.185'),
            ipaddress.ip_address('10.54.42.187')))

        a186 = ipaddress.IPv4Address('10.54.42.186')
        assert ipr[1] == a186
        assert a186 in ipr
