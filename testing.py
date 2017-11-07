from scapy.all import *
a = rdpcap("/home/python/Desktop/testing.pcap")
a[0].show2()

for pkt in a:
    for opt in pkt[TCP].options:
        for o in opt.mptcp:
            if o.dsn:
                print o.dsn

#pkt[MPTCP].dsn
#sniff(offline='/home/python/Desktop/testing.pcap', prn=lambda x: x.show(), filter = "tcp[54] == 30", store=0)



#def newconvo(pkt):
    #sniff(iface=interface, prn=lambda x: x.show(), filter = "tcp[54] == 30", store=0)
#def


