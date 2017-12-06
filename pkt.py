from scapy.all import *

class Packet(object):
    def __init__(self, pkt):
        """
        Rip scapy packet into the bits we need
        :param pkt: A scapy packet
        """
        self.src = "{}:{}".format(pkt[IP].src, pkt[TCP].sport)
        self.dst = "{}:{}".format(pkt[IP].dst, pkt[TCP].dport)
        self.tcp = pkt[TCP]
        self.addr = (self.src, self.dst)

    def get_opts(self):
        """
        :return: set of all the options detected within the packet (will usually be 1).
        """
        opts = set()
        for opt in self.tcp.options:
            # If we con't do attr checks it will throw exceptions at us
            if hasattr(opt, "mptcp"):
                if hasattr(opt.mptcp, "MPTCP_subtype"):
                    if opt.mptcp.MPTCP_subtype == "0x2":
                        opts.add("DSS")
                    if opt.mptcp.MPTCP_subtype == "0x0":
                        opt.add("MPCAPABLE")
                    if opt.mptcp.MPTCP_subtype == "0x1":
                        opt.add("MPJOIN")

            if self.tcp.flags == 0x01:
                opts.add("FIN")

            elif self.tcp.flags == 0x11:
                opts.add("FINACK")

        return opts
    
    def frag_check(self, threshold):
        for opt in self.tcp.options:
            if hasattr(opt, "mptcp"):
                if hasattr(opt.mptcp, "length"):
                    if opt.mptcp.length <= threshold:
                        print "Length smaller then %s bytes, possible fragmentation!" % threshold
