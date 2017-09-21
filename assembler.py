from scapy.all import *


if __name__ == '__main__':
        sniff(iface = "enp0s3", prn = lambda x: x.show(), filter = "tcp[54] == 30", store = 0)