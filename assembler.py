from scapy.all import *
from mscapy.layers.mptcp import *
from mscapy.layers.inet import TCP

class MPTCPConvo(object):
    """
    This is a class used to keep track of MPTCP convos
    """
    def __init__(self, src, dst, dst_port, dst_iface):
        """
        :param src: master source IP
        :param dst: master dest IP
        :param dst_port: fake dest port
        :param dst_iface: fae dest iface
        """
        self.SRC = src
        self.DST = dst
        self.DST_PORT = dst_port
        self.DST_IFACE = dst_iface

    def _process_dss(self, pkt):
        print('This is a DSS packet')

    def _process_add_addr(self, pkt):
        print('This is an ADD_ADDR packet')

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


if __name__ == '__main__':
    sniff(iface = "ens33", prn = lambda x: x.show(), filter = "tcp[54] == 30", store = 0)
