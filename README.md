demodhcpd - A debugging & testing DHCP server
========

This DHCP server (written in Python) was originally developed to diagnose a DHCP problem which turned out to be an incorrectly configured netmask, but has proven useful for other DHCP-related debugging as well, and to have a handy DHCP server which doesn't need any configuration.

A typical run looks like this:

    ./demodhcpd.py -i eth0 --my-ip 10.123.45.1 --ip-range 10.123.45.10-10.123.45.200

demodhcpd can simulate the behavior of different DHCP servers. Pass in `-s isc` to switch to simulating the behavior of the [ISC DHCP server](https://www.isc.org/downloads/dhcp/).

In contrast to other DHCP servers, demodhcpd does not meddle with your network configuration in any way.
