"""
    high level support for doing this and that.

    For import all methods from scapy:
    from scapy.all import *
"""
import logging
import os
import random
import time
from binascii import unhexlify

from scapy.arch import get_if_raw_hwaddr, warning
from scapy.config import conf
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import fuzz, Packet
from scapy.sendrecv import sendp
from scapy.volatile import RandInt, RandMAC
from scapy.compat import raw

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def get_random_mac(half_mac_of_vendor: tuple = (0x00, 0x00, 0x05)):
    """
    Get random mac.
    half_mac_of_vendor - first 3 bytes who identify vendor

    :returns str:
    """
    mac = [half_mac_of_vendor[0], half_mac_of_vendor[1], half_mac_of_vendor[2],
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def get_random_ip():
    """
    Get random ip.

    :returns str:
    """
    return '.'.join('%s' % random.randint(0, 255) for i in range(4))


def get_random_ip_by_subnet192168():
    """
    Get random ip from 192.168.0.0/16.

    :returns str:
    """
    return "192.168.%d.%d" % (random.randint(0, 255), random.randint(0, 255))


def get_random_mac_by_scapy(half_mac_of_vendor="00:00:05"):
    return half_mac_of_vendor + RandMAC()._fix()[len(half_mac_of_vendor):]


def mac_srt2binarray(mac_addr_str):
    """
    refs - stackoverflow.com/questions/12538199/mac-address-conversion-into-byte-array-in-python
    convert mac as str 12-23-34-45-56-67 to mac as binary array 0x12-0x23-0x34-0x45-0x67

    :param mac_addr_str:
    :returns Any: binary array
    """
    return unhexlify(str(mac_addr_str).replace(':', ''))


def send_icmp_by_os_ping(target_host: str = None, iface=None,
                         ping_times=None, wait_time=None,
                         timeout=None, count=None) -> bool:
    """
    todo: documentation

    :returns object:
    """
    if wait_time is not None:
        time.sleep(wait_time)
    exec_cmd = "ping"
    if iface:
        exec_cmd += " -I %s" % iface
    if ping_times:
        exec_cmd += " -w %s" % ping_times
    if timeout:
        exec_cmd += " -W %s" % timeout
    if count:
        exec_cmd += " -c %s" % count
    exec_cmd += " %s" % target_host
    print(exec_cmd)
    return os.system(exec_cmd) == 0


def send_DHCP_request_from_test_host_by_self_mac(iface=None, **kwargs):
    """
    Send a DHCP discover request and return the answer redefine by scapy dhcp_request(iface)
    """
    if conf.checkIPaddr:
        warning(
            "conf.checkIPaddr is enabled, may not be able to match the answer"
        )
    if iface is None:
        iface = conf.iface
    fam, hw = get_if_raw_hwaddr(iface)

    sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68,
                                                                                          dport=67) /  # noqa: E501
          BOOTP(chaddr=hw, xid=RandInt()) / DHCP(options=[("message-type", "discover"), "end"]), iface=iface,
          **kwargs)  # noqa: E501


def send_DHCP_request_from_test_host_with_custom_mac(iface=None, custom_mac=None, **kwargs):
    """
    Send a DHCP discover request and return the answer redefine by scapy dhcp_request(iface)
    """
    if iface is None:
        iface = conf.iface

    fam, hw = get_if_raw_hwaddr(iface)
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=custom_mac) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68,
                                                                                                          dport=67) /  # noqa: E501
          BOOTP(chaddr=hw, xid=RandInt()) / DHCP(options=[("message-type", "discover"), "end"]),
          iface=iface)  # noqa: E501


def send_dhcp_discover(client_mac, iface=None, debug=False):
    """
    todo: documentation
    """
    myxid = random.randint(1, 900000000)
    options = [
        ("message-type", "discover"),
        ("max_dhcp_size", 1500),
        ("client_id", mac_srt2binarray(client_mac)),
        ("lease_time", 10000),
        "end"
    ]
    dhcp_request = Ether(src=client_mac, dst='ff:ff:ff:ff:ff:ff') \
                   / IP(src="0.0.0.0", dst="255.255.255.255") \
                   / UDP(sport=68, dport=67) \
                   / BOOTP(chaddr=mac_srt2binarray(client_mac), xid=myxid, flags=0xFFFFFF) \
                   / DHCP(options=options)
    sendp(dhcp_request,
          iface=iface if iface else conf.iface,
          verbose=1 if debug else 0)


def send_dhcp_discover_fuzzing_boot(client_mac, iface=None, debug=False):
    """
    todo: documentation
    """
    myxid = random.randint(1, 900000000)
    options = [
        ("message-type", "discover"),
        ("max_dhcp_size", 1500),
        ("client_id", mac_srt2binarray(client_mac)),
        ("lease_time", 10000),
        "end"
    ]

    dhcp_request = Ether(src=client_mac, dst='ff:ff:ff:ff:ff:ff') \
                   / IP(src="0.0.0.0", dst="255.255.255.255") \
                   / (UDP(sport=68, dport=67) \
                      / fuzz(BOOTP(chaddr=mac_srt2binarray(client_mac), xid=myxid, flags=0xFFFFFF) \
                             / DHCP(options=options)))
    sendp(dhcp_request,
          iface=iface if iface else conf.iface,
          verbose=1 if debug else 0)


def send_dhcp_discover_fuzzing_dhcp(client_mac, iface=None, debug=False):
    """
    todo: documentation
    """
    myxid = random.randint(1, 900000000)
    options = [
        ("message-type", "discover"),
        ("max_dhcp_size", 1500),
        ("client_id", mac_srt2binarray(client_mac)),
        ("lease_time", 10000),
        "end"
    ]

    dhcp_request = Ether(src=client_mac, dst='ff:ff:ff:ff:ff:ff') \
                   / IP(src="0.0.0.0", dst="255.255.255.255") \
                   / (UDP(sport=68, dport=67)
                      / (BOOTP(chaddr=mac_srt2binarray(client_mac), xid=myxid, flags=0xFFFFFF)
                         / fuzz(DHCP(options=options))))
    sendp(dhcp_request,
          iface=iface if iface else conf.iface,
          verbose=1 if debug else 0)


def send_dhcp_request(client_mac, client_ip, server_ip, iface=None, debug=False):
    """
    todo: documentation
    """
    myxid = random.randint(1, 900000000)
    options = [
        ("message-type", "request"),
        ("requested_addr", client_ip),
        ("server_id", server_ip),
        "end"
    ]
    dhcp_request = Ether(src=client_mac, dst='ff:ff:ff:ff:ff:ff') \
                   / IP(src="0.0.0.0", dst="255.255.255.255") \
                   / UDP(sport=68, dport=67) \
                   / BOOTP(chaddr=mac_srt2binarray(client_mac), ciaddr=client_ip, xid=myxid, flags=0xFFFFFF) \
                   / DHCP(options=options)
    sendp(dhcp_request,
          iface=iface if iface else conf.iface,
          verbose=1 if debug else 0)


def send_dhcp_request_fuzzing(client_mac, client_ip, server_ip, iface=None, debug=False):
    """
    todo: documentation
    """
    myxid = random.randint(1, 900000000)
    options = [
        ("message-type", "request"),
        ("requested_addr", client_ip),
        ("server_id", server_ip),
        "end"
    ]
    dhcp_request = Ether(src=client_mac, dst='ff:ff:ff:ff:ff:ff') \
                   / IP(src="0.0.0.0", dst="255.255.255.255") \
                   / UDP(sport=68, dport=67) \
                   / (BOOTP(chaddr=mac_srt2binarray(client_mac), ciaddr=client_ip, xid=myxid, flags=0xFFFFFF)) \
                   / fuzz(DHCP(options=options))
    sendp(dhcp_request,
          iface=iface if iface else conf.iface,
          verbose=1 if debug else 0)


def send_dhcp_release(client_mac, client_ip, server_mac, server_ip, iface=None, debug=False):
    """
    todo: documentation
    """
    myxid = random.randint(1, 900000000)
    options = [
        ("message-type", "release"),
        ("server_id", server_ip),
        ("client_id", mac_srt2binarray(client_mac)),
        "end"
    ]
    sendp(Ether(src=client_mac, dst=server_mac) /
          IP(src=client_ip, dst=server_ip) /
          UDP(sport=68, dport=67) /
          BOOTP(chaddr=mac_srt2binarray(client_mac), ciaddr=client_ip, xid=myxid, flags=0xFFFFFF) /
          DHCP(options=options),
          iface=iface if iface else conf.iface,
          verbose=1 if debug else 0)


def send_dhcp_release_fuzzing(client_mac, client_ip, server_mac, server_ip, iface=None, debug=False):
    """
    todo: documentation
    """
    myxid = random.randint(1, 900000000)
    options = [
        ("message-type", "release"),
        ("server_id", server_ip),
        ("client_id", mac_srt2binarray(client_mac)),
        "end"
    ]
    sendp(Ether(src=client_mac, dst=server_mac) /
          IP(src=client_ip, dst=server_ip) /
          UDP(sport=68, dport=67) / fuzz(
        BOOTP(chaddr=mac_srt2binarray(client_mac), ciaddr=client_ip, xid=myxid, flags=0xFFFFFF) /
        DHCP(options=options)),
          iface=iface,
          verbose=1)


def send_arp_is_at(src_mac, dst_mac, src_ip, dst_ip, iface=None, debug=False):
    """
    todo: documentation
    """
    sendp(
        Ether(dst=dst_mac, src=src_mac) /
        ARP(op="is-at", psrc=src_ip, pdst=dst_ip, hwsrc=dst_mac),
        iface=iface if iface else conf.iface,
        verbose=1 if debug else 0
    )


def _get_mac_by_iface(iface="wlp2s0"):
    """
    Get mac address as str by network interface.

    :returns str:
    """
    fam, hw = get_if_raw_hwaddr(iface)
    return ':'.join('%02x' % b for b in hw)


def send_DHCP_request_by_self_by_scapy(iface="wlp2s0", dst_eth='ff:ff:ff:ff:ff:ff'):
    """
    Craft request by tester's host

    :param iface:
    :param dst_eth:
    """
    ethernet = Ether(dst=dst_eth, src=_get_mac_by_iface(iface), type=0x800)
    ip = IP(src='0.0.0.0', dst='255.255.255.255')
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=_get_mac_by_iface(iface), ciaddr='0.0.0.0', xid=RandInt(), flags=1)
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    packet = ethernet / ip / udp / bootp / dhcp
    sendp(packet, iface=iface)


def syn_scan(target_dst_ip="192.168.2.202", iface='tap0'):
    """
    todo: documentation
    """
    sendp(Ether() / IP(dst=target_dst_ip) / TCP(sport=random.randint(1024, 65535), dport=range(1, 1000), flags='S',
                                                seq=1000,
                                                options=[('MSS', 1460)], window=1024), iface=iface)


def syn_scan_alt(target_dst_ip="192.168.2.202", iface='tap0'):
    """
    todo: documentation
    """
    sendp(Ether() / IP(dst=target_dst_ip) / TCP(sport=random.randint(1024, 65535), dport=range(1, 1000), flags='S',
                                                seq=1000,
                                                options=[('MSS', 1460)], window=1024), iface=iface)
