from scapy.all import *
from mscapy.layers import *
from mscapy.layers.inet import TCP


#pcap = rdpcap("/home/python/Downloads/testing.pcapng")
pcap = sniff(offline= '/home/python/Downloads/testing.pcapng', prn=lambda x: x.show(), filter = "tcp[54] == 30", store=0)

