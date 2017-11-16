from scapy.all import *
from convos import ConvoHandler

if __name__ == '__main__':
        a = rdpcap('./pcaps/finished.pcap')
        test = ConvoHandler()
        for pkt in a:
            test.handle_packet(pkt)
