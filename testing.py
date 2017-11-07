from mscapy.all import *
mshow2 = mpacket.Packet.show2
a = rdpcap("/home/python/Downloads/testing.pcapng")
a[0].packet.show2()
