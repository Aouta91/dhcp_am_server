# DHCP_am_server 
DHCP server by scapy who can remember DHCP replyes
# Overview 
This DHCP server using DHCP_am server by scapy. Beside DHCP_am server DHCP_am_as_THREAD can store DHCP replies in SQL Lite database.
# Requirements
For run DHCP_am_as_THREAD need install scapy
```shell
pip install scapy
```
```shell
pip3 install scapy
```
For sniffing traffic:
```sh
  sudo   apt -y install tcpdump
```
## Run without sudo (not must)
Find exec files for python и tcpdump 
```sh
  which python3
  which tcpdump
```
Setup rights for scapy: 
```sh
  sudo setcap cap_net_raw=eip /usr/bin/python3.8
  sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
  sudo setcap cap_net_raw=eip  /usr/bin/dumpcap
```
Allow open sockets under 1024 port:
```sh
  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service,cap_net_broadcast=+eip /usr/bin/python3.8
```
## Refs
[link for install Scapy](https://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x)
[Базовая статья по работе со scapy]: https://stackoverflow.com/questions/36215201/python-scapy-sniff-without-root
# Using
For run DHCP_am_as_THREAD need init examplare of DHCP_am class
```python3
    test_dhcp = DhcpAmAsThread(iface="ens37", domain='kostest.local',
                               pool="192.168.2.64/26",
                               network="192.168.2.0/24", gw='192.168.2.180', name_server='10.65.144.52',
                               renewal_time=20, lease_time=40,
                               count=4000, path_temp_db="/tmp/test_dhcp", fuzzing=False)
```
After that run DHCP:
```python3
    test_dhcp.start()
```
Send DHCP request for working DHCP_am server:
```python3    
    send_dhcp_discover(iface="ens37", client_mac=clients_mac)
```
In log will print mac address of DHCP client:
```    
   TODO: insert example
```
Get IP by mac in real time:
```python3    
    clients_ip = test_dhcp.get_macs(requested_mac=clients_mac)
    logging.info("got ip %s of client by mac  %s" % (clients_ip, clients_mac))
```
Stop DHCP server:
```python3
    test_dhcp.stop()
```
# example
Example of using and template store in "dhcp_server_by_scapy_with_sql.py".
```python3
import logging
import pytest
from time import sleep

from ktt.libs.dhcp.DHCP_scapy import DhcpAmAsThread
from ktt.libs.packet_crafter.packet_craft import get_random_mac, \
    send_dhcp_discover

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
    clients_ip = test_dhcp.get_macs(requested_mac=clients_mac)
    logging.info("got ip %s of client by mac  %s" % (clients_ip, clients_mac))
    sleep(1)
    test_dhcp.stop()

if __name__ == "__main__":
    """
        example of using without running in pytest
    """
    test_dhcp_example()
```
