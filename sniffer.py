from scapy.all import *
from scapy.layers.mptcp import *
from scapy.layers.inet import TCP

"""
convos = [{
        (IP:PORT, IP:PORT),
        (IP:PORT, IP:PORT)
    }, {
        (IP:PORT, IP:PORT),
        (IP:PORT, IP:PORT)
    }
]

dss_maps = {
    (IP:PORT, IP:PORT):{
        "DSN": $DSN,
        "SN": $SN,
        "DIFF": $DSS - $SN,
        "master": (IP:PORT, IP:PORT)
    },
    (IP:PORT2,IP:PORT2):{
        "DSN": $DSN,
        "SN": $SN,
        "DIFF": $DSN - $SN,
        "master": (IP:PORT, IP:PORT)
    }
}
"""
convos = set()
dss_maps = dict()


def handle_pkt(pkt):
    """
    :param pkt: scapy packet from sniff:prn
    :return:
    """

    FIN = 0x01
    ACK = 0x10
    FINACK = 0x11

    src_addr = "{ip}:{port}".format(ip=pkt[IP].src, port=pkt[IP].sport)
    dst_addr = "{ip}:{port}".format(ip=pkt[IP].dst, port=pkt[IP].dport)
    convo_addr = (src_addr, dst_addr)
    generic_addr = frozenset({src_addr, dst_addr})

    dss = {}
    has_dss = False

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


        #TODO ADD_ADDR detection and handling - done / next check and advise
        for opt in pkt[TCP].options:
            try:
                MP_CAPABLE = opt.mptcp.MPTCP_subtype == "0x0"
                snd_key = opt.mptcp.snd_key
            except:
                pass

            """
            if MP_CAPABLE and senders_key:
                generate sublow token
                store in dss_map dict
            """

        for opt in pkt[TCP].options:
            try:
                MP_JOIN = opt.mptcp.MPTCP_subtype == "0x1"
                rcv_token = opt.mptcp.rcv_token

            except:
                pass
            """
        if MP_JOIN and subflow_token:
            find matching convo
            add to convos set
            relate to master
            verify HMACs (sentry)
        """
        #TODO replace seq and send (ie. assemler)

    elif has_dss:
        convos.add(frozenset({src_addr, dst_addr}))
        dss_maps[convo_addr] = dss

        #TODO replace seq and send (ie. assembler)

if __name__ == '__main__':
        a = rdpcap('./pcaps/finished.pcap')
        for pkt in a:
            handle_pkt(pkt)
