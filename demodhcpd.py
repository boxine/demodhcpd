#!/usr/bin/env python3
# A DHCP server to demonstrate problems with some clients
# Important note: The focus of this server is reproducibility, debugability, and
# simplicity, not performance or reliability.
# For this reason, there's no timeout of assignments.
# DO NOT USE IN PRODUCTION.

from __future__ import unicode_literals, print_function

import argparse
import binascii
import collections
import grp
import os
import pwd
import socket
import struct
import sys


import ipaddress  # If this fails, either use Python 3 or run pip install ipaddress


DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPACK = 5
DHCPNAK = 6

try:
    SO_BINDTODEVICE = socket.SO_BINDTODEVICE
except AttributeError:  # Python 2
    SO_BINDTODEVICE = 25


try:
    PermissionError
except NameError:  # Python2, just catch any socket errors
    PermissionError = socket.error


def make_bytes(b):
    if sys.version_info[0] < 3:
        return bytearray(b)

    if isinstance(b, bytes):
        return b

    return bytes(b)


MAGIC_COOKIE = b'\x63\x82\x53\x63'

DHCPAssignment = collections.namedtuple('DHCPAssignment', ['mac', 'hostname', 'ip'])


def format_mac(mac_addr):
    return ':'.join('%02x' % b for b in mac_addr)


def ip_range(start, end):
    cur = start
    while cur <= end:
        yield cur
        cur = cur + 1


class NoAddressAvailable(Exception):
    pass


class AddressPool(object):
    def __init__(self, all_addrs):
        assert isinstance(all_addrs, list)
        self.all_addrs = all_addrs
        self.assignments = {}  # ip -> DHCPAssignment
        self.by_mac = {}  # mac -> DHCPAssignment
        self.p = 0

    def get_addr(self, mac):
        prev = self.by_mac.get(mac)
        if prev:
            return prev.ip

        tries = 0
        n = len(self.all_addrs)
        while tries < n:
            if self.all_addrs[self.p] in self.assignments:
                self.p = (self.p + 1) % n
                tries += 1
            else:
                return self.all_addrs[self.p]
        raise NoAddressAvailable()

    def assign(self, addr, mac, hostname):
        """ Returns True iff the address could be assigned """

        if addr not in self.all_addrs:
            return

        cur = self.assignments.get(addr)
        if cur is not None and cur.mac != mac:
            return False  # already assigned

        ass = DHCPAssignment(mac, hostname, addr)
        self.assignments[addr] = ass
        self.by_mac[mac] = ass

        return True


class DHCPServer(object):
    def __init__(self, my_ip, dns_ip, pool, subnet_len, craftfunc, log):
        self.my_ip = my_ip
        self.dns_ip = dns_ip
        self.pool = pool
        self.craftfunc = craftfunc
        self.log = log
        self.subnet_len = subnet_len

    def craft_nak(self, transaction_id, broadcast_flag, mac_addr):
        assert len(mac_addr) == 6

        return ((
            b'\x02' +      # BOOTREPLY
            b'\x01\x06' +  # Ethernet (6 bytes addresses)
            b'\x00' +      # hops
            transaction_id +
            b'\x00\x00' +  # secs
            (b'\x80\x00' if broadcast_flag else b'\x00\x00') +  # broadcast flag
            b'\0\0\0\0' +  # ciaddr (not applicable)
            b'\0\0\0\0' +  # yiaddr: none (this is a NAK)
            b'\0\0\0\0' +  # siaddr
            b'\0\0\0\0' +  # giaddr
            mac_addr + (b'\0' * 10) +  # chaddr + padding
            (b'\0' * 64) +   # sname
            (b'\0' * 128) +  # file
            MAGIC_COOKIE +
            b'\x35\x01' + struct.pack('!B', DHCPNAK) +  # DHCP Message type: NAK
            b'\x36\x04' + self.my_ip.packed +    # DHCP Server Identifier
            b'\xff'
        ), ('255.255.255.255' if broadcast_flag else str(offer_ip), 68))

    def craft_offer_ack(self, dhcp_type, transaction_id, broadcast_flag, offer_ip, mac_addr):
        return self.craftfunc(
            dhcp_type=dhcp_type,
            transaction_id=transaction_id,
            broadcast_flag=broadcast_flag,
            offer_ip=offer_ip,
            mac_addr=mac_addr,
            server_ip=self.my_ip,
            router_ip=self.my_ip,
            packed_dns=self.dns_ip.packed,
            subnet_len=self.subnet_len,
        )

    def handle(self, packet):
        # See RFC 2131 for more details

        packet = make_bytes(packet)

        # op
        if packet[0] == 2:
            raise ValueError('We got a DHCP reply. Another DHCP server in this network?')
        if packet[0] != 1:
            raise ValueError('Invalid value for OP: %d' % packet[0])

        # htype
        if packet[1] != 1:
            raise ValueError('Unsupported hardware type: %d' % packet[1])
        # hlen
        hlen = packet[2]
        if hlen != 6:
            raise ValueError('Unsupported hardware address length: %d' % packet[2])
        # hops
        if packet[3] != 0:
            raise ValueError('Unsupported hop count: %d' % packet[3])

        transaction_id = packet[4:8]
        # secs: 2 bytes we ignore

        # flags
        flags_int = struct.unpack('!H', packet[10:12])[0]
        if flags_int & 0x7f:
            raise ValueError('lower 15 flags should all be 0!')
        broadcast_flag = (flags_int >> 15) != 0

        # ciaddr: 4 bytes we ignore
        # yiaddr: 4 bytes we ignore

        # siaddr
        if packet[20:24] != b'\0\0\0\0':
            raise ValueError('Strange sidaddr: Should always be 0 for requests')
        # giaddr
        if packet[24:28] != b'\0\0\0\0':
            raise ValueError('Strange giaddr: Should always be 0 unless using an agent')

        # chaddr
        mac_addr = packet[28:28 + hlen]
        if packet[28+hlen:44] != b'\0' * (16 - hlen):
            raise ValueError('Strange chaddr padding: Should always be 0')

        # sname
        if packet[44:108] != b'\0' * 64:
            raise ValueError('Strange sname: Should always be 0 in DHCP')
        # file
        if packet[108:236] != b'\0' * 128:
            raise ValueError('Strange file: Should always be 0 in DHCP')

        assert len(packet) >= 236
        options = packet[236:]
        if len(options) > 312:
            raise ValueError('Options length is outside of spec: %d' % len(options))

        if options[:4] != MAGIC_COOKIE:
            raise ValueError(
                'Missing magic DHCP cookie; options start with %s instead of %s' %
                (binascii.hexlify(options[:4]), binascii.hexlify(MAGIC_COOKIE))
            )

        pos = 4
        dhcp_type = None
        requested_ip = None
        requested_hostname = None
        requested_params = None
        while pos < len(options):
            code = options[pos]
            if code == 0:  # Pad
                pos += 1
                continue
            if code == 255:  # End
                for p in range(pos + 1, len(options)):
                    if options[p] != 0:
                        raise ValueError('Expected only 0 after End of Options')
                break

            olen = options[pos + 1]
            odata = options[pos + 2:pos + 2 + olen]
            if code == 12:  # hostname
                assert olen >= 1
                requested_hostname = odata.decode('ascii')
            elif code == 50:  # Requested IP address
                assert olen == 4
                requested_ip = ipaddress.ip_address(bytes(odata))
            elif code == 51:  # address lease time
                assert olen == 4
                # we ignore this value for now
            elif code == 53:  # DHCP message type
                assert olen == 1
                dhcp_type = options[pos + 2]
            elif code == 54:  # DHCP server identifier
                assert olen == 4
                assert odata == self.my_ip.packed
            elif code == 55:  # parameter request list
                assert olen >= 1
                requested_params = list(odata)
            elif code == 57:  # Maximum DHCP message size
                assert olen == 2
                max_size = struct.unpack('!H', odata)[0]
                assert max_size >= 576
            elif code == 60:  # vendor class identifier
                assert olen >= 1
                # we don't care, seems Android-specific
            elif code == 61:  # client identifier
                assert olen >= 2
                # we ignore this value for now
            elif code == 81:  # client FQDN, see https://tools.ietf.org/html/rfc4702
                assert olen >= 1
                # we ignore this value for now
            else:
                self.log(
                    'Unsupported request option %d at position %d, skipping' %
                    (code, 42 + 236 + pos))

            pos += 2 + olen
        else:
            raise ValueError('Last option was not End')

        if dhcp_type is None:
            raise ValueError('DHCP type is missing')

        if dhcp_type == DHCPDISCOVER:
            self.log(
                '> DHCPDISCOVER from %s %s%s' % (
                    requested_hostname or '',
                    format_mac(mac_addr),
                    ' (params: %s)' % requested_params if requested_params else ''))
            offer_ip = self.pool.get_addr(mac_addr)

            answer, to = self.craft_offer_ack(
                dhcp_type=DHCPOFFER,
                transaction_id=transaction_id,
                broadcast_flag=broadcast_flag,
                offer_ip=offer_ip,
                mac_addr=mac_addr
            )
            self.log('< DHCPOFFER %s to %s %s' % (offer_ip, to[0], format_mac(mac_addr)))
            return answer, to
        elif dhcp_type == DHCPREQUEST:
            if not requested_ip:
                answer, to = self.craft_nak(
                    transaction_id=transaction_id,
                    broadcast_flag=broadcast_flag,
                    mac_addr=mac_addr
                )
                self.log(
                    '< DHCPNAK (no IP address requested) to %s %s' %
                    (to[0], format_mac(mac_addr)))
                return answer, to

            self.log(
                '> DHCPREQUEST %s from %s %s%s' % (
                    requested_ip, requested_hostname or '',
                    format_mac(mac_addr),
                    ' (params: %s)' % requested_params if requested_params else ''))

            assignment_success = self.pool.assign(
                requested_ip, mac_addr, requested_hostname)
            if assignment_success:
                answer, to = self.craft_offer_ack(
                    dhcp_type=DHCPACK,
                    transaction_id=transaction_id,
                    broadcast_flag=broadcast_flag,
                    offer_ip=requested_ip,
                    mac_addr=mac_addr
                )
                self.log('< DHCPACK %s to %s %s' % (requested_ip, to[0], format_mac(mac_addr)))
                return answer, to
            else:
                answer, to = self.craft_offer_ack(
                    dhcp_type=DHCPNAK,
                    transaction_id=transaction_id,
                    broadcast_flag=broadcast_flag,
                    offer_ip=ipaddress.ip_address('0.0.0.0'),
                    mac_addr=mac_addr
                )
                self.log(
                    '< DHCPNAK (do not take %s) to %s %s' %
                    (requested_ip, to[0], format_mac(mac_addr)))
                return answer, to
        else:
            raise ValueError('Unsupported DHCP message type %d' % dhcp_type)

    def serve(self, sock):
        while True:
            packet, addr = sock.recvfrom(4096)
            answer, to = self.handle(packet)
            sock.sendto(answer, to)


# Rerun this program with sudo
def elevate():
    os.execvp(
        '/usr/bin/sudo',
        ['python3'] + sys.argv +
        [
            '--drop-user', str(os.getuid()),
            '--drop-group', str(os.getgid()),
            '--no-elevation'
        ])
    assert False, 'never reached'


def craft_udhcpd_broken(
        dhcp_type,
        transaction_id, broadcast_flag, offer_ip, mac_addr,
        server_ip, subnet_len, router_ip, packed_dns):

    assert len(mac_addr) == 6
    packed_subnet_mask = struct.pack(
        '!I', int(ipaddress.ip_address(offer_ip.packed)) | (0xffffffff >> subnet_len))
    packed_lease_time = b'\x00\x01\x51\x80'  # 1 day

    return ((
        b'\x02' +      # BOOTREPLY
        b'\x01\x06' +  # Ethernet (6 bytes addresses)
        b'\x00' +      # hops
        transaction_id +
        b'\x00\x00' +  # secs
        b'\x80\x00' +  # broadcast flag and 15 empty bits: always set with udhcpd
        b'\0\0\0\0' +  # ciaddr (not applicable)
        offer_ip.packed +  # yiaddr
        b'\0\0\0\0' +  # siaddr
        b'\0\0\0\0' +  # giaddr
        mac_addr + (b'\0' * 10) +  # chaddr + padding
        (b'\0' * 64) +   # sname
        (b'\0' * 128) +  # file
        MAGIC_COOKIE +
        b'\x35\x01' + struct.pack('!B', dhcp_type) +  # DHCP Message Type
        b'\x36\x04' + server_ip.packed +    # DHCP Server Identifier
        b'\x33\x04' + packed_lease_time +   # DHCP Lease Time: 1 day (hardcoded)
        b'\x01\x04' + packed_subnet_mask +  # Subnet Mask
        b'\x03\x04' + router_ip.packed +    # Router
        b'\x06\x04' + packed_dns +          # DNS Server
        b'\xff' +      # End
        (b'\0' * 26)   # Padding - udhcp does this (completely useless)
    ), ('255.255.255.255', 68))


def craft_udhcpd(
        dhcp_type,
        transaction_id, broadcast_flag, offer_ip, mac_addr,
        server_ip, subnet_len, router_ip, packed_dns):

    assert len(mac_addr) == 6
    packed_subnet_mask = struct.pack('!I', (0xffffffff << (32 - subnet_len)) & 0xffffffff)
    packed_lease_time = b'\x00\x01\x51\x80'

    return ((
        b'\x02' +      # BOOTREPLY
        b'\x01\x06' +  # Ethernet (6 bytes addresses)
        b'\x00' +      # hops
        transaction_id +
        b'\x00\x00' +  # secs
        b'\x80\x00' +  # broadcast flag and 15 empty bits: always set with udhcpd
        b'\0\0\0\0' +  # ciaddr (not applicable)
        offer_ip.packed +  # yiaddr
        b'\0\0\0\0' +  # siaddr
        b'\0\0\0\0' +  # giaddr
        mac_addr + (b'\0' * 10) +  # chaddr + padding
        (b'\0' * 64) +   # sname
        (b'\0' * 128) +  # file
        MAGIC_COOKIE +
        b'\x35\x01' + struct.pack('!B', dhcp_type) +  # DHCP Message Type
        b'\x36\x04' + server_ip.packed +    # DHCP Server Identifier
        b'\x33\x04' + packed_lease_time +   # DHCP Lease Time: 1 day (hardcoded)
        b'\x01\x04' + packed_subnet_mask +  # Subnet Mask
        b'\x03\x04' + router_ip.packed +    # Router
        b'\x06\x04' + packed_dns +          # DNS Server
        b'\xff' +      # End
        (b'\0' * 26)   # Padding - udhcp does this (completely useless)
    ), ('255.255.255.255', 68))


def craft_isc(
        dhcp_type,
        transaction_id, broadcast_flag, offer_ip, mac_addr,
        server_ip, subnet_len, router_ip, packed_dns):

    assert len(mac_addr) == 6
    packed_subnet_mask = struct.pack('!I', (0xffffffff << (32 - subnet_len)) & 0xffffffff)
    packed_lease_time = b'\x00\x00\x1c\x20' if dhcp_type == DHCPOFFER else b'\x00\x00\x02\x58'

    return ((
        b'\x02' +      # BOOTREPLY
        b'\x01\x06' +  # Ethernet (6 bytes addresses)
        b'\x00' +      # hops
        transaction_id +
        b'\x00\x00' +  # secs
        (b'\x80\x00' if broadcast_flag else b'\x00\x00') +  # broadcast flag
        b'\0\0\0\0' +  # ciaddr (not applicable)
        offer_ip.packed +  # yiaddr
        b'\0\0\0\0' +  # siaddr
        b'\0\0\0\0' +  # giaddr
        mac_addr + (b'\0' * 10) +  # chaddr + padding
        (b'\0' * 64) +   # sname
        (b'\0' * 128) +  # file
        MAGIC_COOKIE +
        b'\x35\x01' + struct.pack('!B', dhcp_type) +  # DHCP Message Type
        b'\x36\x04' + server_ip.packed +    # DHCP Server Identifier
        b'\x33\x04' + packed_lease_time +   # DHCP Lease Time
        b'\x01\x04' + packed_subnet_mask +  # Subnet Mask
        b'\x03\x04' + router_ip.packed +       # Router
        b'\x06\x04' + packed_dns +          # DNS Server
        b'\xff' +      # End
        (b'\0' * 26)   # Padding - isc does this (completely useless)
    ), ('255.255.255.255' if broadcast_flag else str(offer_ip), 68))


CRAFT_FUNCS = {
    'udhcpd_broken': craft_udhcpd_broken,
    'udhcpd': craft_udhcpd,
    'isc': craft_isc,
}


def main():
    parser = argparse.ArgumentParser('A demonstration DHCP server')
    parser.add_argument(
        '-i', '--interface', metavar='INTERFACE',
        default='wlan0', help='Listen to the specified interface')
    parser.add_argument(
        '--my-ip', metavar='IP_ADDRESS',
        default='10.54.42.1',
        help='The IP address of the server (assumed to be the router as well)')
    parser.add_argument(
        '--dns-ip', metavar='IP_ADDRESS',
        default='1.1.1.1',
        help='IP of the DNS server (default: %(default)s)')
    parser.add_argument(
        '--ip-range', metavar='STARTIP-ENDIP',
        default='10.54.42.10-10.54.42.250',
        help='Range of IP addresses to give out (default: %(default)s)'
    )
    parser.add_argument(
        '--netmask-length', metavar='SIZE',
        default=24,
        type=int,
        help='Length of the netmask in bits, between 0 and 32 (default: %(default)s )'
    )
    parser.add_argument(
        '--drop-user', metavar='USER',
        help='Drop privileges to this user')
    parser.add_argument(
        '--drop-group', metavar='GROUP',
        help='Drop privileges to this group')
    parser.add_argument(
        '--no-elevation', action='store_false', dest='elevation',
        help='Do not try to elevate with sudo if necessary'
    )
    parser.add_argument(
        '-s', '--simulate', metavar='DHCP_SERVER', dest='craftfunc',
        default='udhcpd', choices=['udhcpd', 'udhcpd_broken', 'isc'],
        help=(
            'The DHCP server to simulate ' +
            '(one of "udhcpd", "udhcpd_broken", "isc". ' +
            ' default: %(default)s)'
        )
    )
    parser.add_argument(
        '-q', '--quiet', action='store_true',
        help='Do not output chatter'
    )
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(
            socket.SOL_SOCKET, SO_BINDTODEVICE,
            args.interface.encode('ascii') + b'\0')
    except PermissionError:
        if args.elevation:
            if not args.quiet:
                print('Insufficient privileges, retrying with sudo ...')
            return elevate()
        else:
            raise

    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(('', 67))

    # Drop privileges
    if args.drop_group:
        os.setgroups([])
        try:
            gid = grp.getgrnam(args.drop_group).gr_gid
        except KeyError:
            gid = grp.getgrgid(int(args.drop_group)).gr_gid
        os.setgid(gid)
    if args.drop_user:
        try:
            uid = pwd.getpwnam(args.drop_user).pw_uid
        except KeyError:
            uid = pwd.getpwuid(int(args.drop_user)).pw_uid
        os.setuid(uid)

    start, end = args.ip_range.split('-')
    address_list = list(ip_range(
        ipaddress.ip_address(start),
        ipaddress.ip_address(end)))

    craftfunc = CRAFT_FUNCS[args.craftfunc]

    dhcpd = DHCPServer(
        ipaddress.ip_address(args.my_ip),
        ipaddress.ip_address(args.dns_ip),
        AddressPool(address_list),
        args.netmask_length,
        craftfunc, print)
    dhcpd.serve(s)


if __name__ == '__main__':
    main()
