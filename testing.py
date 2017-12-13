import sys
from scapy.all import *
from datetime import datetime

a = rdpcap("./mpjoin.pcap")
pkt = a[1]
pkt2 = pkt[IP]
ls(pkt[IP])
