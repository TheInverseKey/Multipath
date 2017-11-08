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
        "DSS": $DSS,
        "SN": $SN,
        "DIFF": $DSS - $SN,
        "FIN": False
    },
    "IP:PORT->IP:PORT":{
        "DSS": $DSS,
        "SN": $SN,
        "DIFF": $DSS - $SN,
        "FIN": False
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

    # TODO check for DSS
    has_dss = False
    dss = {}


    if frozenset({src_addr, dst_addr}) in convos:
        if has_dss:
            dss_maps[convo_addr] = dss

        #TODO FIN detection and handling
        """
        if ACK and FIN_detected_other_way:
            remove_convo;
            remove_dss_map;
        """

        #TODO ADD_ADDR detection and handling
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
