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
convos = []
dss_maps = dict()


def handle_pkt(pkt):
    """
    :param pkt: scapy packet from sniff:prn
    :return:
    """
    src_addr = "{ip}:{port}".format(ip=pkt[IP].src, port=pkt[IP].sport)
    dst_addr = "{ip}:{port}".format(ip=pkt[IP].dst, port=pkt[IP].dport)
    convo_addr = "{src}->{dst}".format(src=src_addr, dst=dst_addr)
    reverse_addr = "{dst}->{src}".format(src=src_addr, dst=dst_addr)


    # TODO check for dss - done / next check

    dss = {}
    has_dss = False
    for opt in pkt[TCP].options:

        try:
            opt.mptcp.MPTCP_subtype = "0x2"
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

    if frozenset({src_addr, dst_addr}) in convos:
        if has_dss:
            dss_maps[convo_addr] = dss

        #TODO FIN detection and handling

            pkt[TCP].flag = "F"

            try:
                pkt[TCP].flags = "FA"
                print "FIN ACK"
            except:
                pass

        """
        if ACK and FIN_detected_other_way:
            remove_convo;
            remove_dss_map;
        """

        #TODO ADD_ADDR detection and handling - done / next check and advise
        for opt in pkt[TCP].options:
            try:
                # checking for add_addr

                opt.mptcp.MPTCP_subtype = "0x3"
                has_addr = True
            except:
                has_addr = False

        for opt in pkt[TCP].options:
            try:
                # checking for mp_join

                opt.mptcp.MPTCP_subtype = "0x1"
                has_join = True
            except:
                has_join = False
        """
        if previous_ADD_ADDR and MP_JOIN:
            convo# = get_convo_from_convos()
            convos[convo#].add((IP:PORT, IP:PORT))
        """
        #TODO replace seq and send (ie. assemler)

    elif has_dss:
        convos.append({(src_addr, dst_addr)})
        dss_maps[convo_addr] = dss

        #TODO replace seq and send (ie. assembler)
