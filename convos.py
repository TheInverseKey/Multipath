import binascii
from scapy.all import *
from pkt import Packet

class ConvoHandler(object):
    """
    Manages the multiple active convos
    """
    def __init__(self):
        self.convos = set()
        self.master_flows = {}
        self.subflows = {}

    def handle_packet(self, scapy_pkt):
        """
        Get packet flags/options and then act accordingly
        :param scapy_pkt:
        """
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
    def pkt_send(self):
        
        ip = IP(src=src_IP, dst=dst_IP, proto=6, len=length, chksum=chksum)
        send(eth/ip/tcp/payload)

    def function1(self, pkt1, new_seq, src=None, dst=None)
    """
        Convert Sequence Number to Interger
	:param pkt1: 
        :param new_seq:    int packet sequence number
	:param src: 
	:param dst:
 	"""
    pkt = pkt1
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
     

    def add_master(self, addr, snd_key):
        """
        Add a new convo to the master_flows dict (and derive token from key)
        :param addr:    tuple with (src, dst)
        :param snd_key: hex value of sender's key in packet
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
        Add a new convo to the subflows dict and find its master
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
        Update a flows DSS map
        :param addr:    tuple (src, dst)
        :param dsn:     int packet dsn
        :param seq_num: int packet sequence number
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
        Remove flow dict entry and optionally the convo frozenset entry
        :param addr: tuple (src, dst)
        """
        generic_addr = frozenset(addr)
        if generic_addr in self.convos:
            if addr in self.master_flows:
                del self.master_flows[addr]
            elif addr in self.subflows:
                del self.subflows[addr]

            if end_convo:
                self.convos.remove(generic_addr)
