
import sys
from scapy.all import *
from datetime import datetime

#test_content = """this is only a test""" + datetime.now().strftime("%m/%y %H:%M:%S")
"""
eth = Ether(dst=MAC_dst, src=MAC_src, type=eth_type)
ip = IP(src="192.168.1.69", dst="127.0.0.1", proto=6)/"Sequence number 1234"
tcp = TCP(sport=80, dport=80, flags='PA', seq=1234, ack=1)
a = ip/tcp/test_content
a.display()
send(a)
"""


a = rdpcap("./mpjoin.pcap")
a[1].show2()
pkt = a[1]

self = pkt
self.tcp = pkt[TCP] #TODO: remove this, it's redundant thanks to self.pkt addition
self.addr = (self.src, self.dst)

"""
def get_opts(self):
    opts = set()
    for opt in self.tcp.options:
        # If we con't do attr checks it will throw exceptions at us
        try:
            if opt.mptcp.MPTCP_subtype == "0x2":
                opts.add("DSS")
            elif opt.mptcp.MPTCP_subtype == "0x0":
                opts.add("MPCAPABLE")
            elif opt.mptcp.o.subtype == "0x1":
                opts.add("MPJOIN")
                print "mpjoin"

        except AttributeError:
            pass

        if self.tcp.flags == 0x01:
            opts.add("FIN")

        elif self.tcp.flags == 0x11:
            opts.add("FINACK")
    print opts
    return opts
"""


def get_opts(self):
    for opt in pkt[TCP].options:
        if opt.kind == 30:
            for o in opt:
                try:
                    print vars(o)
                except:
                    pass

    for opt in pkt[TCP].options:
            try:
                MP_JOIN = opt.mptcp.MPTCP_subtype == "MP_JOIN"
                print MP_JOIN
            except:
                pass
"""

convos = set()
dss_maps = dict()

dss = {}
has_dss = False



def get_packet_type(pkt):
    dss = {}
    has_dss = False
    snd_key = None
    rcv_token = None

    for opt in pkt[TCP].options:
        try:
            print opt.mptcp.MPTCP_subtype
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
            
            MP_CAPABLE = opt.mptcp.MPTCP_subtype == "0x0"
            if MP_CAPABLE:
                snd_key = opt.mptcp.snd_key
                break
        except:
            pass

        try:
            
            MP_JOIN = opt.mptcp.MPTCP_subtype == "0x1"
            if MP_JOIN:
                rcv_token = opt.mptcp.rcv_token
                print "rcv token"
        except:
            pass



"""
"""
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

        
        if snd_key:
            token = hashlib.sha1(binascii.unhexlify(snd_key)).hexdigest()[:8]
            dss_maps[convo_addr]['token']=token

        else:
                print "MP_CAPABLE found but no key :("

        
        for addrs, options in dss_maps.iteritems():
            if options['token'] == rcv_token:
                dss_maps[convo_addr]['master'] = addrs
                break

    elif has_dss:
        convos.add(frozenset({src_addr, dst_addr}))
        dss_maps[convo_addr] = dss

"""
#def send_packet():


        #ip = IP(frag=0, proto=tcp, dst=dst)
        #tcp =TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, chksum=, )
        #data = packet[TCP].payload
        #sr1(IP(frag=0, proto=tcp, dst=dst)/TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags=pkt[TCP].flags, chksum=, )/packet[TCP].payload)
#    test_content = """this is only a test""" + datetime.now().strftime("%m/%y %H:%M:%S")
#    ip = IP(src="192.168.1.69", dst="127.0.0.1")/"Sequence number 1234"
#    tcp = ip / TCP(sport="80", dport="80", flags='PA',seq="1234", ack=1) / test_content
#    tcp.display()
    # print("length of packet {}".format(len(tcp)))
#       send(tcp)

#send_packet()


get_opts(self)
#get_packet_type(pkt)


