from scapy.all import *


def start_sniffing(handler, iface, filter="tcp[54] == 30"):
    """
    :param handler:     Function to handle packets
    :param interface:   Interface to sniff
    :return:            None, runs indefinitely
    """
    log_location = 'idk right now'
    try:
        sniff(iface = iface, prn = handler, filter = filter, store = 0)
    except (KeyboardInterrupt, SystemExit):
        print('Cleaning up the mess we made, logs can be found here: %s' %log_location)
        #TODO: cleanup our mess