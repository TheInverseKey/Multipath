from scapy.all import *

class Packet(object):
    def __init__(self, pkt):
        """
        Rip scapy packet into the bits we need
        :param pkt: A scapy packet
        """
        self.src = "{}:{}".format(pkt[IP].src, pkt[TCP].sport)
        self.dst = "{}:{}".format(pkt[IP].dst, pkt[TCP].dport)
        self.tcp = pkt[TCP] #TODO: remove this, it's redundant thanks to self.pkt addition
        self.addr = (self.src, self.dst)
        self.pkt = pkt

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

    def convert(self, new_seq, src=None, dst=None):
        """
        Takes self.pkt and changes sequence number and src/dst ip/port if specified
        :param new_seq: the new seq number (DSN)
        :param src: tuple {srcip, srcport}
        :param dst: tuple {dstip, dstport}
        """
        self.pkt[TCP].seq = new_seq

        if src:
            src_ip = src[0]
            src_port = src[1]
            self.pkt[IP].src = src_ip
            self.pkt[TCP].sport = src_port

        if dst:
            dst_ip = dst[0]
            dst_port = dst[1]
            self.pkt[IP].dst = dst_ip
            self.pkt[TCP].dport = dst_port

    def pkt_send(self, iface=None):
        """
        Sends self.pkt out specified iface or 'lo' if not specified
        :param iface: Name of interface to send to
        """
        if not iface:
            iface = "lo"

        sendp(self.pkt, iface=iface)

    def frag_check(self, threshold):
        for opt in self.tcp.options:
            if hasattr(opt, "mptcp"):
                if hasattr(opt.mptcp, "length"):
                    if opt.mptcp.length <= threshold:
                        print "Length smaller then %s bytes, possible fragmentation!" % threshold
