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
    "IP:PORT->IP:PORT":{
        "DSN": $DSN,
        "SN": $SN,
        "DIFF": $DSS - $SN
    },
    "IP:PORT->IP:PORT":{
        "DSN": $DSN,
        "SN": $SN,
        "DIFF": $DSN - $SN
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
    convo_addr = "{src}->{dst}".format(src=src_addr, dst=dst_addr)
    generic_addr = frozenset({src_addr, dst_addr})


    # TODO check for dss - done / next check

    dss = {}
    has_dss = False
    for opt in pkt[TCP].options:

        try:
            if opt.mptcp.MPTCP_subtype == "0x2":
                print "This is a dss packet"
                has_dss = True
                SN = pkt[TCP].seq
                DSN = opt.mptcp.dsn
                DIFF = DSN - SN
                FIN = False
                dss = {
                    "DSN": DSN,
                    "SN": SN,
                    "DIFF": DIFF,
                    "FIN": FIN
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
            has_addr =False
            try:
                # checking for add_addr

                opt.mptcp.MPTCP_subtype = "0x3"
                has_addr = True
            except:
                pass

        for opt in pkt[TCP].options:
            has_join = False
            try:
                # checking for mp_join

                opt.mptcp.MPTCP_subtype = "0x1"
                has_join = True
            except:
                pass

        """
        if previous_ADD_ADDR and MP_JOIN:
            convo# = get_convo_from_convos()
            convos[convo#].add((IP:PORT, IP:PORT))
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
