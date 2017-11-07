from scapy.all import *
a = rdpcap("./testing.pcap")
a[0].show()
pkt = a[0]
for opt in pkt[TCP].options:
    try:
        print opt.mptcp.dsn
    except:
        pass

#pkt[MPTCP].dsn
#sniff(offline='/home/python/Desktop/testing.pcap', prn=lambda x: x.show(), filter = "tcp[54] == 30", store=0)



#def newconvo(pkt):
    #sniff(iface=interface, prn=lambda x: x.show(), filter = "tcp[54] == 30", store=0)
#def


