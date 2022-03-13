"""
    example of using DHCP server that allows you to get the ip address
"""
# pylint: disable=import-error
# pylint: disable=logging-not-lazy
# pylint: disable=too-few-public-methods
# pylint: disable=line-too-long
# pylint: disable=pointless-string-statement
# pylint: disable=attribute-defined-outside-init
# pylint: disable=useless-object-inheritance
# pylint: disable=too-many-instance-attributes
# pylint: disable=invalid-name

import logging
from time import sleep


from dhcp_byscapy import DhcpAmAsThread
from packet_craft import get_random_mac, send_dhcp_discover

DHCP_WORK_TIME_IN_SECONDS = 100000


def test_dhcp_example():
    """
        example of using to running in pytest at interface tap0
    :param :
    """
    test_dhcp = DhcpAmAsThread(iface="ens37", domain='kostest.local',
                               pool="192.168.2.64/26",
                               network="192.168.2.0/24", gw='192.168.2.180', name_server='10.65.144.52',
                               renewal_time=20, lease_time=40,
                               count=4000, path_temp_db="/tmp/test_dhcp", fuzzing=False)
    clients_mac = get_random_mac()
    test_dhcp.start()
    sleep(5)
    send_dhcp_discover(iface="ens37", client_mac=clients_mac)
    sleep(DHCP_WORK_TIME_IN_SECONDS)
    ip_kisg = test_dhcp.get_macs(requested_mac=clients_mac)
    logging.info("got ip %s of client by mac  %s" % (ip_kisg, clients_mac))
    sleep(1)
    test_dhcp.stop()

if __name__ == "__main__":
    """
        example of using without running in pytest
    """
    test_dhcp_example()