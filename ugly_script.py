from scapy.all import *
from mscapy.layers.mptcp import *
from mscapy.layers.inet import TCP


class MPTCPConvo(object):
    """
    This is a class used to keep track of MPTCP convos
    """

    def __init__(self, addr_a, addr_b, dst_iface):
        """
        :param addr_a: Tuple: master address a (IP, Port)
        :param addr_b: Tuble: master address b (IP, Port)
        :param dst_iface: fae dest iface
        """
        self.MASTER_A = addr_a
        self.MASTER_B = addr_b
        self.DST_IFACE = dst_iface
        self.a_addrs = [addr_a]
        self.b_addrs = [addr_b]

    def _process_dss(self, pkt):
        print('This is a DSS packet')

    def _process_add_addr(self, pkt):
        print('This is an ADD_ADDR packet')
        # TODO parse the packet and add new address to either a_addrs or b_addrs

    def _process_mp_join(self, pkt):
        print('This is an MP_JOIN packet')

    def _process_pkt(self, pkt):
        print('This is another kind of packet')

    def process_packet(self, pkt):
        """
        Takes a packet, classifies it, calls the appropriate processor
        :param pkt: the packet from Scapy
        :return:
        """
        packet_methods = {
            'DSS': self._process_dss,
            'ADD_ADDR': self._process_add_addr,
            'MP_JOIN': self._process_mp_join
        }

        for opt in pkt[TCP].options:
            for o in opt.mptcp:
                subtype = MPTCP_subtypes[o.subtype]
                if subtype in list(packet_methods.keys()):
                    """Calls function based on subtype"""
                    packet_methods[subtype](pkt)
                else:
                    self.process_packet(pkt)

class PktHandler(object):
    def assign_pkt(self, pkt):
        self.pkt = pkt
        pkt_methods = {
            'DSS': self.handle_dss,
            'ADD_ADDR': self.handle_add_addr
        }

        for opt in self.pkt[TCP].options:
            for o in opt.mptcp:
                subtype = MPTCP_subtypes[o.subtype]
                if subtype in pkt_methods.keys():
                    """Calls function based on subtype"""
                    pkt_methods[subtype]

    def handle_dss(self):
        self.dss = {
            #'DSN': pkt[MPTCP].dsn
            #'SN':  pkt[TCP].seq
            #'DIFF': pkt[MPTCP].dsn - pkt[TCP].seq
        }