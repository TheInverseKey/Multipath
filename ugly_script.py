import hashlib
import binascii
from scapy.all import *
from scapy.layers.mptcp import *
from scapy.layers.inet import TCP


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
        # Find if master or sub
        for flow_addr in self.master_flows.keys():
            if addr == flow_addr:
                self.master_flows[addr].update({
                    'dsn': dsn,
                    'diff': dsn - seq_num
                })


"""
class MasterFlow(object):
    def __init__(self, src, dst, snd_key):
        self.addr = {src, dst}
        self.token = hashlib.sha1(binascii.unhexlify(snd_key)).hexdigest()[:8]
"""
