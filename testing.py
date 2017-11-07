from scapy.all import *
from mscapy import *
from mscapy.layers import *
from mscapy.layers.inet import TCP


a= rdpcap("/home/python/Downloads/testing.pcapng")
a[0].show2()