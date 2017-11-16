from scapy.all import *
a = rdpcap("./mpjoin.pcap")
#a[1].show2()
pkt = a[1]

convos = set()
dss_maps = dict()

dss = {}
has_dss = False
"""Should this function return values?"""


def get_packet_type():
    dss = {}
    has_dss = False
    snd_key = None
    rcv_token = None

    for opt in pkt[TCP].options:
        try:
            if opt.mptcp.MPTCP_subtype == "0x2":
                print "DSS"
                has_dss = True
                SN = pkt[TCP].seq
                DSN = opt.mptcp.dsn

                dss = {
                    "DSN": DSN,
                    "SN": SN,
                    "DIFF": DSN - SN
                }

        except:
            pass

        try:
            FIN = pkt[TCP].flags == 0x01
        except:
            pass

        try:
            FIN_ACK = pkt[TCP].flags == 0x011
        except:
            pass

        try:
            """"MP CAPABLE then get sdn_key"""
            MP_CAPABLE = opt.mptcp.MPTCP_subtype == "0x0"
            if MP_CAPABLE:
                snd_key = opt.mptcp.snd_key
                break
        except:
            pass

        try:
            """MP_JOIN rcv_token"""
            MP_JOIN = opt.mptcp.MPTCP_subtype == "0x1"
            if MP_JOIN:
                rcv_token = opt.mptcp.rcv_token
                print "rcv token"
        except:
            pass


"""Needs to take arguments, question is what ones?"""


def handle_packet():
    
    if frozenset({src_addr, dst_addr}) in convos or True:
        if has_dss or True:
            dss_maps[convo_addr] = dss

            if pkt[TCP].flags == 0x01:
                print "FIN"
                del dss_maps[convo_addr]

            if pkt[TCP].flags == 0x11:
                print "FIN ACK"
                del dss_maps[convo_addr]
                convos.discard(generic_addr)

        """This might be spaced wrong"""
        if snd_key:
            token = hashlib.sha1(binascii.unhexlify(snd_key)).hexdigest()[:8]
            dss_maps[convo_addr]['token']=token

        else:
                print "MP_CAPABLE found but no key :("

        """This might be spaced wrong also"""
        for addrs, options in dss_maps.iteritems():
            if options['token'] == rcv_token:
                dss_maps[convo_addr]['master'] = addrs
                break

    elif has_dss:
        convos.add(frozenset({src_addr, dst_addr}))
        dss_maps[convo_addr] = dss


def send_packet(pkt, dst, sport,):

    """This is the message for the packet."""
    """packet[TCP].payload"""
    """check for master ip address"""
    while self.master_flow[addr] == True:

        #ip = IP(frag=0, proto=tcp, dst=dst)
        #tcp =TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, chksum=, )
        #data = packet[TCP].payload
        sr1(IP(frag=0, proto=tcp, dst=dst)/TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, chksum=, )/packet[TCP].payload)








