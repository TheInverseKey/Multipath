from scapy.all import *

#PyCharm Hack
TCP=TCP
IP=IP

class Packet(object):

    def __init__(self, pkt):

        """
        Rip scapy packet into the bits we need
        :param pkt: A scapy packet object
        """
        self.src = (pkt[IP].src, pkt[TCP].sport)
        self.dst = (pkt[IP].dst, pkt[TCP].dport)
        self.addr = (self.src, self.dst)
        self.pkt = pkt
        self.seq = pkt[TCP].seq

    def get_opts(self):
        """
        :return: set of all the options detected within the packet (will usually be 1).
        """
        opts = set()
        for subtype in self.get_mp_opt('subtype'):
            """
            2 -> DSN/DSS
            0 -> MPCAPABLE
            1 -> MPJOIN
            """
            if subtype == 2:
                try:
                    self.dsn = self.get_mp_opt('dsn').next()
                except StopIteration:
                    pass
                opts.add("DSS")

            elif subtype == 0:
                try:
                    self.snd_key = self.get_mp_opt('snd_key').next()
                except StopIteration:
                    pass
                opts.add("MPCAPABLE")

            elif subtype == 1:
                try:
                    self.rcv_token = self.get_mp_opt('rcv_token').next()
                except StopIteration:
                    pass
                opts.add("MPJOIN")

        if self.pkt[TCP].flags == 0x01:
            opts.add("FIN")

        elif self.pkt[TCP].flags == 0x11:
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

    def send(self, iface=None):
        """
        Sends self.pkt out specified iface or 'lo' if not specified
        :param iface: Name of interface to send to
        """
        if not iface:
            iface = "lo"

        #is_mp = lambda x: type(x) in [scapy.layers.inet.TCPOption_MP, scapy.layers.inet.TCPOption_SAck]
        #new_ops = [i for i in self.pkt[TCP].options if not is_mp(i)]
        #self.pkt[TCP].options = new_ops

        new_pkt = Ether(src=self.pkt[Ether].src,
                        dst=self.pkt[Ether].dst)/\
                  IP(version=self.pkt[IP].version,
                     proto=self.pkt[IP].proto,
                     src=self.pkt[IP].src,
                     dst=self.pkt[IP].dst)/\
                  TCP(sport=self.pkt[TCP].sport,
                      dport=self.pkt[TCP].dport,
                      seq=self.pkt[TCP].seq,
                      flags=self.pkt[TCP].flags)/\
                  self.pkt.payload

        sendp(new_pkt, iface=iface)

    def get_mp_opt(self, attr):
        """
        Returns the value(s) of an mptcp sub-option in a scapy packet
        :param attr: the name of the mptcp option to get the value(s) of
        :return: the value(s) of the sub-option
        """
        for opt in self.pkt[TCP].options:
            if hasattr(opt, 'mptcp'):
                if hasattr(opt.mptcp, attr):
                    yield getattr(opt.mptcp, attr, None)

    def frag_check(self, threshold):
        mp_length = self.get_mp_opt('length').next()
        if mp_length <= threshold:
            print "Length smaller then %s bytes, possible fragmentation!" % threshold


if __name__ == '__main__':
    import inspect
    from pprint import pprint
    a = rdpcap("./websiteloaded.pcap")
    pkt = a[8]
    p = Packet(pkt)
    print p.get_opts()
    p.convert(6969)
    print p.pkt[TCP].seq
    for opt in p.pkt[TCP].options:
        if hasattr(opt, 'mptcp'):
            if hasattr(opt.mptcp, 'length'):
                opt.mptcp.length = 1
    p.frag_check(2)
    for opt in p.pkt[TCP].options:
        if opt.kind == 30:
            print p.pkt[TCP].flags
            print opt.summary
