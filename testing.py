import sys
from scapy.all import *
from datetime import datetime
from pprint import pprint
a = rdpcap("./demo.pcap")
types = []
for pkt in a:
    pkt[TCP].options = [i for i in pkt[TCP].options if type(i) is not scapy.layers.inet.TCPOption_MP]
    types += [type(i) for i in pkt[TCP].options]
types = set(types)
pprint(types)

