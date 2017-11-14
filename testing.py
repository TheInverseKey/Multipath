from scapy.all import *
a = rdpcap("./mpjoin.pcap")
#a[1].show2()
pkt = a[1]

convos = set()
dss_maps = dict()

dss = {}
has_dss = False


def get_packet():
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
            FIN = pkt[TCP].flags == 0x01
            FIN_ACK = pkt[TCP].flags == 0x011

            """"MP CAPABLE then get sdn_key"""
            MP_CAPABLE = opt.mptcp.MPTCP_subtype == "0x0"
            if MP_CAPABLE:
                snd_key = opt.mptcp.snd_key
                break

            """MP_JOIN rcv_token"""
            MP_JOIN = opt.mptcp.MPTCP_subtype == "0x1"
            if MP_JOIN:
                rcv_token = opt.mptcp.rcv_token
                print "rcv token"
        except:
            pass




























def get_dsn(pkt):
    for opt in pkt[TCP].options:
        try:
            dss = opt.mptcp.dsn
            opt.mptcp.MPTCP_subtype = "0x2"

            print "This is a dss packet"
            print opt.mptcp.dsn
        except:
            pass


def get_dss(pkt):
    for opt in pkt[TCP].options:
        try:
            opt.mptcp.MPTCP_subtype = "0x2"

            print "This is a dss packet"
        except:
            pass


def get_dss_sn(pkt):
        try:
            seq = pkt[TCP].seq
            print pkt[TCP].seq
        except:
            pass

def get_fin_ack(pkt):
    try:
        pkt[TCP].flags = "FA"
        print "FIN ACK"
    except:
        pass
def get_send_key(pkt):
    for opt in pkt[TCP].options:
        try:
            snd_key = opt.mptcp.snd_key
            print snd_key
        except:
            pass

def get_rcv_token(pkt):
    for opt in pkt[TCP].options:
        try:
            rcv_token = opt.mptcp.rcv_token
            print rcv_token
        except:
            pass



#get_rcv_token(pkt)
#get_send_key(pkt)
#get_dsn(pkt)
#get_dss(pkt)
#get_dss_sn(pkt)
#get_fin_ack(pkt)


