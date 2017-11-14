import hashlib
import binascii
from scapy.all import *
from scapy.layers.mptcp import *
from scapy.layers.inet import TCP


class ConvoHandler(object):
    def __init__(self):
        self.convos = set()
        self.master_flows = {}

    def add_master(self, src, dst, snd_key):
        generic_addr = frozenset([src, dst])
        self.convos.add(generic_addr)
        # Derive token from key
        snd_key = binascii.unhexlify(snd_key)
        token = hashlib.sha1(snd_key).hexdigest()[:8]

        self.master_flows[{src, dst}] = {
            "token": token
            "subflows": {}
        }

    def add_subflow(self, src, dst, token):
        # Find matching recv_key
        for flow in self.master_flows.items()

"""
class MasterFlow(object):
    def __init__(self, src, dst, snd_key):
        self.addr = {src, dst}
        self.token = hashlib.sha1(binascii.unhexlify(snd_key)).hexdigest()[:8]
"""
