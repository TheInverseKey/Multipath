from scapy.all import *
from mscapy.layers.inet import TCP
from mscapy import packet as mpacket
mshow2 = mpacket.Packet.show2
a = rdpcap("/home/python/Downloads/testing.pcapng")
a[0].packet.show2()
