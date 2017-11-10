from scapy.all import *
a = rdpcap("./mpjoin.pcap")
#a[1].show2()
pkt = a[1]



def get_dsn(pkt):
    for opt in pkt[TCP].options:
        try:
            dss = opt.mptcp.dsn
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

get_rcv_token(pkt)
#get_send_key(pkt)
#get_dsn(pkt)
#get_dss(pkt)
#get_dss_sn(pkt)
#get_fin_ack(pkt)


#def getMpOption(tcp):
#    """Return a generator of mptcp options from a scapy TCP() object"""
#    for opt in tcp.options:
#        if opt.kind == 30:
#            yield opt.mptcp
