import binascii
from scapy.all import *


class ConvoHandler(object):
    def __init__(self):
        self.convos = set()
        self.master_flows = {}
        self.subflows = {}

    def add_master(self, addr, snd_key):
        """
        :param addr:    tuple with (src, dst)
        :param snd_key: hex value of sender's key in packet
        :return:
        """
        generic_addr = frozenset(addr)
        self.convos.add(generic_addr)
        # Derive token from key
        snd_key = binascii.unhexlify(snd_key)
        token = hashlib.sha1(snd_key).hexdigest()[:8]

        self.master_flows[addr] = {
            'token': token
        }

    def add_subflow(self, addr, token):
        """
        :param addr:  tuple (src, dst)
        :param token: receiver's token
        :return:
        """
        generic_addr = frozenset(addr)
        self.convos.add(generic_addr)
        # Find matching recv_key
        for flow, info in self.master_flows.items():
            if info['token'] == token:
                master_addr = addr[::-1]
                if self.master_flows[master_addr]:
                    self.subflows[addr] = {
                        'master': master_addr
                    }
                else:
                    print "Something is fishy! {} should belong to master flow {}," \
                          "but we have no record of that flow!".format(addr,master_addr)

    def update_dss(self, addr, dsn, seq_num):
        """
        :param addr:    tuple (src, dst)
        :param dsn:     int packet dsn
        :param seq_num: int packet sequence number
        :return:
        """
        generic_addr = frozenset(addr)
        if generic_addr in self.convos:
            dss_dict = {
                'dsn': dsn,
                'diff': dsn - seq_num
            }

            if addr in self.master_flows:
                self.master_flows[addr].update(dss_dict)

            elif addr in self.subflows:
                self.subflows[addr].update(dss_dict)

        else:
            print "Oh shit, we don't have a record for flow {}".format(addr)

    def teardown(self, addr):
        """
        :param addr: tuple (src, dst)
        :return:
        """
        generic_addr = frozenset(addr)
        if generic_addr in self.convos:
            if addr in self.master_flows:
                del self.master_flows[addr]
            elif addr in self.subflows:
                del self.subflows[addr]

            self.convos.remove(generic_addr)
