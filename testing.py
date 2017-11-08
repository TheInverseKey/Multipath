from scapy.all import *
a = rdpcap("./testing.pcap")
pkt = a[0]


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
            print pkt[TCP].seq
        except:
            pass

get_dsn(pkt)
get_dss(pkt)
get_dss_sn(pkt)
