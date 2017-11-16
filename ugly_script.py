import binascii
from scapy.all import *


class ConvoHandler(object):
    def __init__(self):
        self.convos = set()
        self.master_flows = {}
        self.subflows = {}

    def handle_packet(self, scapy_pkt):
        pkt = Packet(scapy_pkt)
        opts = pkt.get_opts()
        if "DSS":
            self.update_dss(pkt.addr, pkt.tcp.options.mptcp.dsn, pkt.tcp.seq)
        if "FIN" in opts:
            self.teardown(pkt.addr),
        elif "FINACK" in opts:
            self.teardown(pkt.addr, end_convo=True)
        elif "MP_CAPABLE" in opts:
            self.add_master(pkt.addr, pkt.tcp.options.mptcp.snd_key),
        elif "MP_JOIN" in opts:
            self.add_subflow(pkt.addr, pkt.tcp.options.mptcp.rcv_token),

        #TODO
        #pkt.convert()
        #pkt.send()
        while self.master_flow[addr] == True:
            sr1(IP(frag=0, proto=tcp, dst=dst)/TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags,
                                                 chksum=, )/packet[TCP].payload)

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


    def add_subflow(self, addr, rcv_token):
        """
        :param addr:  tuple (src, dst)
        :param token: receiver's token
        :return:
        """
        generic_addr = frozenset(addr)
        self.convos.add(generic_addr)
        # Find matching recv_key
        for flow, info in self.master_flows.items():
            if info['token'] == rcv_token:
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

    def teardown(self, addr, end_convo=False):
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

            if end_convo:
                self.convos.remove(generic_addr)

class Packet(object):
    def __init__(self, pkt):
        self.src = "{}:{}".format(pkt[IP].src, pkt[TCP].sport)
        self.dst = "{}:{}".format(pkt[IP].dst, pkt[TCP].dport)
        self.tcp = pkt[TCP]
        self.addr = (self.src, self.dst)
        self.generic_addr = frozenset(addr)

    def get_opts(self):
        opts = set()
        for opt in self.tcp.options:
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

            elif self.tcp.flags == 0x011:
                opts.add("FINACK")

        return opts