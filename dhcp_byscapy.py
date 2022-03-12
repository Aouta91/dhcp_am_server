"""
    high level support for doing this and that.
    This module include reerited DHCP_am by Scapy
"""

import logging
import sqlite3
import os
from datetime import datetime
from threading import Thread, Event

# pylint: disable=import-error
# pylint: disable=logging-not-lazy
# pylint: disable=too-few-public-methods
# pylint: disable=line-too-long
# pylint: disable=pointless-string-statement
# pylint: disable=attribute-defined-outside-init
# pylint: disable=useless-object-inheritance
# pylint: disable=too-many-instance-attributes
# pylint: disable=invalid-name

from argparse import ArgumentParser

from scapy.layers.dhcp import BOOTP_am, DHCP

from scapy.utils import atol, itom, ltoa
import scapy.modules.six as six
from scapy.base_classes import Net

from scapy.layers.inet import IP
from scapy.compat import raw
from scapy.config import conf
from scapy.data import ETH_P_ALL

from ktt.libs.packet_crafter.payloads import get_fuzz_dhcp_layer_gen_set # TODO: take method

try:
    from collections.abc import Iterable
except ImportError:
    """
        For backwards compatibility.  This was removed in Python 3.8
    """
    from collections import Iterable

PARSER = ArgumentParser()
TABLE_OF_NAME_MACS = "macs"
TABLE_OF_NAME_REPLIES = "replies"


def _get_moment_as_str():
    """

    :return: current time as string
    """
    return datetime.now().strftime('%Y.%m.%d_%H:%M:%S.%f')


class redefineDHCP_am(BOOTP_am):  # pylint: disable=too-few-public-methods
    function_name = "dhcpd"

    def __init__(self, *args, **kwargs):
        """
        reddefine DHCP_am by scapy
        https://scapy.readthedocs.io/en/latest/_modules/scapy/layers/dhcp.html  # DHCP_am
        https://gist.github.com/yosshy/4551b1fe3d9af63b02d4
        add SQL lite storage for writing requests
        :param args:
        :param kwargs:
        """
        super(BOOTP_am, self).__init__(*args, **kwargs)
        self.time = datetime.now()
        name_db = self.path_temp_db
        if os.path.isfile(name_db):
            os.remove(name_db)
        logging.info("Temp DB: %s" % str(name_db))
        self.connection = sqlite3.connect(str(name_db))
        self.cursor = self.connection.cursor()
        self.table_of_name_macs = TABLE_OF_NAME_MACS
        self.table_of_names_replies = TABLE_OF_NAME_REPLIES
        self.dict_of_telling_macs = {}

        logging.info("table_of_name_macs: %s, table_of_names_replies: %s" % (
            self.table_of_name_macs, self.table_of_names_replies))
        try:
            self.cursor.execute("create table %s (mac CHAR(17) not NULL primary key, \
                   ip CHAR(15) ,hostname text, bornTime text)" % (self.table_of_name_macs))
        except sqlite3.IntegrityError:
            logging.info("table %s is exist. Reinit table ..." % self.table_of_name_macs)
            logging.info("self.path_temp_db %s" % self.path_temp_db)
            self.cursor.execute(
                "DROP table %s " % self.table_of_name_macs)
            self.cursor.execute("create table %s (mac CHAR(17) not NULL primary key, \
                   ip CHAR(15),  hostname text, bornTime text)" % self.table_of_name_macs)
        try:
            self.cursor.execute("create table %s (timeOfReplies CHAR(22) not NULL primary key, \
                   mac CHAR(17), ip CHAR(15), hostname text)" % self.table_of_names_replies)
        except sqlite3.IntegrityError:
            logging.info("tab  %s is exist. Reinit table ..." % self.table_of_names_replies)
            self.cursor.execute(
                "DROP table %s " % self.table_of_names_replies)
            self.cursor.execute("create table %s (timeOfReplies CHAR(22) not NULL primary key, \
                   mac CHAR(17), ip CHAR(15), hostname text)" % self.table_of_names_replies)

    def make_reply(self, req):
        resp = BOOTP_am.make_reply(self, req)
        if DHCP in req:
            dhcp_options = [(op[0], {1: 2, 3: 5}.get(op[1], op[1]))
                            for op in req[DHCP].options
                            if isinstance(op, tuple) and op[0] == "message-type"]  # noqa: E501
            dhcp_options += [("server_id", self.gw),
                             ("domain", self.domain),
                             ("router", self.gw),
                             ("name_server", self.name_server),
                             ("broadcast_address", self.broadcast),
                             ("subnet_mask", self.netmask),
                             ("renewal_time", self.renewal_time),
                             ("lease_time", self.lease_time),
                             "end"
                             ]
            resp /= DHCP(options=dhcp_options)
        return resp

    def print_reply(self, req, reply):
        """

        :param req: request packet object
        :param reply: reply packet object
        """
        dst_client_ip = reply.getlayer(IP).dst
        dst_client_mac = reply.dst
        logging.info("Test Reply %s to %s" % (dst_client_ip, dst_client_mac))
        if dst_client_mac not in self.dict_of_telling_macs.keys():
            logging.debug("Current keys in DHCP DB: %s" % self.dict_of_telling_macs.keys())
            logging.info("Updating macs dict %s : %s" % (dst_client_mac, dst_client_ip))
            self.dict_of_telling_macs[dst_client_mac] = dst_client_ip
            logging.debug("Dict of macs %s" % self.dict_of_telling_macs)
            logging.info("Macs dict was update %s : %s" % (self.dict_of_telling_macs.get(dst_client_mac), dst_client_ip))
            try:
                self.cursor.execute(
                    "INSERT into %s values ('%s','%s','None', '%s')" % (
                        self.table_of_name_macs, str(dst_client_mac), str(dst_client_ip), _get_moment_as_str()))
                self.connection.commit()
            except sqlite3.IntegrityError as e:
                logging.info("mac is exist in db %s: \n %s" % self.table_of_name_macs, e)
            try:
                self.cursor.execute(
                    "INSERT into %s values ('%s', '%s','%s','None')" % (
                        self.table_of_names_replies, _get_moment_as_str(), str(dst_client_mac), str(dst_client_ip)))
                self.connection.commit()
            except sqlite3.IntegrityError as e:
                logging.info("Error occurred: ", e)

    def read_macs_from_db(self):
        """
        connection to tmp db and reading table with mac addresses table
        """
        self.cursor.execute(f'select * from {self.table_of_name_macs}')
        out = self.cursor.fetchall()
        logging.info("read_macs_from_db: %s" % self.cursor.fetchall())
        return out

    def get_ip_by_mac_owner(self, requested_mac='12:24:54:5f:5f:5f'):
        """
        get ip by mac owner
        """
        logging.debug("Current DB of MACs: %s " % self.dict_of_telling_macs)
        getted_ip = self.dict_of_telling_macs.get(requested_mac)
        if getted_ip:
            logging.info("IP %s was got by %s" % (getted_ip , requested_mac))
        else:
            logging.info("DB of DHCP does not contain mac: %s " % requested_mac)
        return self.dict_of_telling_macs.get(requested_mac)

    def read_replies_from_db(self):
        """
        connection to tmp db and reading table with replieses table
        """
        self.cursor.execute('select * from %s' % self.table_of_names_replies)
        logging.info("read_replies_from_db: %s" % self.cursor.fetchall())

    def parse_options(self, pool=Net("192.168.1.128/25"), network="192.168.1.0/24", gw="192.168.1.1",  # noqa: E501
                      domain="localnet", renewal_time=60, lease_time=1800, name_server="10.65.144.52",
                      path_temp_db=None):
        """
        this method getting params by .yaml config file

        :param pool: pool of telling ip addresses
        :param network: working network
        :param gw: gateway of working network
        :param path_temp_db: path to sqllite db of working info

        This params will insert to dhcp response
        :param domain:
        :param renewal_time:
        :param lease_time:
        """
        self.path_temp_db = path_temp_db
        self.domain = domain
        netw, msk = (network.split("/") + ["32"])[:2]
        msk = itom(int(msk))
        self.netmask = ltoa(msk)
        self.name_server = name_server
        self.network = ltoa(atol(netw) & msk)
        self.broadcast = ltoa(atol(self.network) | (0xffffffff & ~msk))
        self.gw = gw
        if isinstance(pool, six.string_types):
            pool = Net(pool)
        if isinstance(pool, Iterable):
            pool = [k for k in pool if k not in [gw, self.network, self.broadcast]]  # noqa: E501
            pool.reverse()
        if len(pool) == 1:
            pool, = pool
        self.pool = pool
        self.lease_time = lease_time
        self.renewal_time = renewal_time
        self.leases = {}


class redefineDHCP_am_fuzz(redefineDHCP_am):

    def make_reply(self, req):
        resp = BOOTP_am.make_reply(self, req)
        if DHCP in req:
            dhcp_options = [(op[0], {1: 2, 3: 5}.get(op[1], op[1]))
                            for op in req[DHCP].options
                            if isinstance(op, tuple) and op[0] == "message-type"]  # noqa: E501
            dhcp_options += [("server_id", (self.gw)),
                             ("domain", "\'test.com\'"),
                             ("router", self.gw),
                             ("name_server", self.name_server),
                             ("name_server", "8.8.8.8"),
                             ("broadcast_address", self.broadcast),
                             ("subnet_mask", self.netmask),
                             ("renewal_time", self.renewal_time),
                             ("lease_time", self.lease_time),
                             "end"
                             ]
            resp /= (DHCP(options=dhcp_options))
            logging.debug(resp.summary())
            logging.debug("raw DHCP last field %s " % resp.lastlayer())
            worked_dhcp_layer = resp.lastlayer()
            dhcp_code = raw(worked_dhcp_layer)[0:3]
            logging.debug("Original DHCP req code: %s " % str(dhcp_code))
            if dhcp_code == b'5\x01\x02':
                logging.debug("Responding correct answer ")
            else:
                payload_craft = dhcp_code + get_fuzz_dhcp_layer_gen_set()[3:]
                resp["BOOTP"].remove_payload()
                resp /= payload_craft
            logging.debug("result  resp DHCP pkt: \n\t %s" % str(resp))
        return resp


class DhcpAmAsThread(object):
    """
    Example got from http://sebastiandahlgren.se/2014/06/27/running-a-method-as-a-background-thread-in-python/#:~:text=Here's%20a%20little%20code%20snippet,the%20application%20continues%20it's%20work.&text=until%20the%20application%20exits.


    Threading example class
    The run() method will be started and it will run in the background
    until the application exits.

    Scapy DHCP_am run as daemonize thread in background


    """

    def __init__(self, interval=1000, iface='tap0', domain='example.com', pool='192.168.10.0/24',
                 network='192.168.10.0/24', gw='192.168.10.254', name_server="10.65.144.52", renewal_time=6,
                 lease_time=6, count=40000,
                 path_temp_db="/tmp/s_dhcp.db", fuzzing=False):
        self.interval = interval
        self.iface = iface
        self.domain = domain
        self.pool = Net(pool)
        self.network = network
        self.gateway = gw
        self.renewal_time = renewal_time
        self.lease_time = lease_time
        self.count = count
        self.name_server = name_server
        self.running_flag = True
        self.thread = Thread(target=self.run, args=())
        self.thread.daemon = True  #
        self._stop = Event()
        self.path_temp_db = path_temp_db
        self.fuzzing = fuzzing
        self.table_of_name_macs = "macs"
        self.table_of_names_replies = "replies"
        logging.debug("Try to clear exist db \'%s\'" % path_temp_db)
        if os.path.isfile(path_temp_db):
            logging.debug("clear exist db \'%s\'" % path_temp_db)
            os.remove(path_temp_db)
        self.path_temp_db = path_temp_db
        self.socket = None

    def check_alive(self):
        """

        :rtype: object
        """
        return self.thread.is_alive()

    def start(self):
        """

        :rtype: object
        """
        # self.run() # uncomit for legacy
        self.thread.start()

    def stop(self):
        """

        :rtype: object
        """
        self._stop.set()

    def stopped(self):
        """

        :rtype: object
        """
        return self._stop.is_set()

    def run(self):
        """
        Method that runs forever

        :rtype: object
        """

        logging.info(
            'Loop of DHCP_am server. iface: %s , Domain: %s,  pool: %s, network: %s, gateway: %s, name_server: %s, renewal_time: %s,  lease_time: %s, count: %s' % (
                self.iface, self.domain, self.pool, self.network, self.gateway, self.name_server, self.renewal_time,
                self.lease_time,
                self.count))

        logging.debug(
            'DHCP_am server is alive: %s' % self.check_alive)
        logging.info("loop")
        if self.fuzzing:
            logging.info("Start fuzzing DHCP")
            self.dhcp_serer = redefineDHCP_am_fuzz(iface=self.iface, domain=self.domain, pool=self.pool,
                                                   network=self.network,
                                                   gw=self.gateway, renewal_time=self.renewal_time,
                                                   lease_time=self.lease_time,
                                                   count=self.count, path_temp_db=self.path_temp_db,
                                                   name_server=self.name_server)
        else:
            logging.info("Start classic DHCP")
            self.dhcp_serer = redefineDHCP_am(iface=self.iface, domain=self.domain, pool=self.pool,
                                              network=self.network,
                                              gw=self.gateway, renewal_time=self.renewal_time,
                                              lease_time=self.lease_time,
                                              count=self.count, path_temp_db=self.path_temp_db,
                                              name_server=self.name_server)
        # For correct threading workaround from: https://blog.skyplabs.net/python-sniffing-inside-thread/
        self.socket = conf.L2listen(type=ETH_P_ALL, iface=self.iface, filter="ip")
        self.dhcp_serer(opened_socket=self.socket, stop_filter=lambda x: self.stopped())
        logging.debug("Stopped dhcp server")
        """
        uncomment if need to support legacy run
            try:
                self.dhcp_serer.run()
            except Exception as e:
                logging.info("Run DHCP_am with legacy function ....%s" % e)
                pass
        """

    def get_macs(self, requested_mac='12:24:54:5f:5f:5f'):
        """

        :rtype: IP address by mac
        """
        logging.info("Trying get IP by mac: %s" % requested_mac)
        return self.dhcp_serer.get_ip_by_mac_owner(requested_mac=requested_mac)
