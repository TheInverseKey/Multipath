import binascii
import hashlib
from scapy.all import *
from pkt import Packet
import logging
import json
import os

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler('Convo.log')
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


#PyCharm Hack
TCP = TCP

class ConvoHandler(object):
    """
    Manages the multiple active multipath convos
    """
    def __init__(self):
        self.convos = set()
        self.master_flows = {}
        self.subflows = {}
        self.ip_relationships = {}

    def handle_packet(self, scapy_pkt):
        """
        Get packet flags/options and then act accordingly
        :param scapy_pkt: a packet object from scapy library
        """
        is_MPTCP = False
        if not any(x == 30 for x in scapy_pkt[TCP].options):
            return

        self.pkt = Packet(scapy_pkt)
        for opt in self.pkt.get_opts():
            if opt != 'DSS':
                print 'MPTCP Subtype:', opt
            if "DSS" in opt:
                if hasattr(self.pkt, 'dsn'):
                    self.update_dss(self.pkt.addr, self.pkt.dsn, self.pkt.seq)

            if "FIN" in opt:
                self.teardown(self.pkt.addr)

            if "FINACK" in opt:
                self.teardown(self.pkt.addr, end_convo=True)

            if "MPCAPABLE" in opt:
                if hasattr(self.pkt, 'snd_key'):
                    snd_key = format(self.pkt.snd_key, 'x')
                    self.add_master(self.pkt.addr, snd_key)

            if "MPJOIN" in opt:
                if hasattr(self.pkt, 'rcv_token'):
                    self.add_subflow(self.pkt.addr, format(self.pkt.rcv_token, 'x'))

    def push_packet_as_single_stream(self):
        #TODO Maybe put this in it's own function, idk anymore man
        if not hasattr(self, 'pkt'):
            raise AttributeError('You need a packet to do this')

        # if packet is in a subflow, retrieve its master from dict and get the seq diff
        if self.pkt.addr in self.subflows.keys():
            final_addr = self.subflows[self.pkt.addr]['master']

            try:
                diff = self.subflows[self.pkt.addr]['diff']

            except KeyError:
                print self.subflows[self.pkt.addr]
                return

        # handle packet as master (if the packet got this far it should already have a record in the dict)
        else:
            final_addr = self.pkt.addr

            try:
                diff = self.master_flows[self.pkt.addr]['diff']

            except KeyError:
                return

        try:
            self.pkt.convert(abs(self.pkt.seq + diff), src=final_addr[0], dst=final_addr[1])

        except KeyError:
            logger.error('Oh shit, we have a packet but no listed DSN for it! \n '
                         'Here\'s the adress sequence number for reference: \n '
                         'addr: {} \n seq: {}'.format(self.pkt.addr, self.pkt.seq))

        logger.info('Packet to Send: {} -> {} : {}'.format(self.pkt.pkt[TCP].sport, self.pkt.pkt[TCP].dport, self.pkt.seq))
        self.pkt.send()


    def add_master(self, addr, snd_key):
        """
        Add a new convo to the master_print opts if opts != 'DSS' flows dict (and derive token from key)
        :param addr:    tuple with (src, dst)
        :param snd_key: hex value of sender's key in packet
        """
        logger.info('Add Master: {}'.format(addr))
        self.ip_relationships[str(addr)] = []
        generic_addr = frozenset(addr)
        self.convos.add(generic_addr)
        # Derive token from key
        snd_key = binascii.unhexlify(snd_key)
        token = hashlib.sha1(snd_key).hexdigest()[:8]
        self.master_flows[addr] = {
            'token': token
        }

    def add_subflow(self, addr, rcv_token):
        """
        Add a new convo to the subflows dict and find its master
        :param addr:  tuple (src, dst)
        :param token: receiver's token
        :return:
        """
        logger.info('Add Subflow: {}'.format(addr))
        generic_addr = frozenset(addr)
        self.convos.add(generic_addr)
        # Find matching recv_key
        for flow, info in self.master_flows.iteritems():
            if info['token'] == rcv_token:
                master_addr = flow[::-1]
                if master_addr in self.master_flows.keys():
                    self.ip_relationships[str(master_addr)].append(str(addr))
                    self.subflows[addr] = {
                        'master': master_addr
                    }
                else:
                    logger.error('Something is fishy! {} should belong to master flow {},' \
                          'but we have no record of that flow!'.format(addr,master_addr))

    def update_dss(self, addr, dsn, seq_num):
        # type: (list, int, int) -> None
        """
        Update a flows DSS map
        :param addr:    tuple (src, dst)
        :param dsn:     int packet dsn
        :param seq_num: int packet sequence number
        """
        logger.info('Update DSS: {}'.format(addr))
        generic_addr = frozenset(addr)
        if generic_addr in self.convos:
            dss_dict = {
                'dsn': dsn,
                'diff': dsn - seq_num #TODO examine if this is necessary (I don't think it is)
            }

            if addr in self.master_flows.keys():
                self.master_flows[addr].update(dss_dict)

            elif addr in self.subflows.keys():
                self.subflows[addr].update(dss_dict)

        else:
            logger.error("We don't have a record for flow {}".format(addr))

    def teardown(self, addr, end_convo=False):
        """
        Remove flow dict entry and optionally the convo frozenset entry
        :param addr: tuple (src, dst)
        :param end_convo: Used when a FINACK is given, remove convo frozenset entry
        """
        generic_addr = frozenset(addr)
        if generic_addr in self.convos:
            if addr in self.master_flows:
                del self.master_flows[addr]
                self.export_ips(addr)
            elif addr in self.subflows:
                del self.subflows[addr]

            if end_convo:
                self.convos.remove(generic_addr)

    def export_ips(self, addr, file="ip_relationships.json"):
        if os.path.isfile(file):
            perms = 'a'
        else:
            perms = 'w+'

        with open(file, perms) as log_file:
            log_file.write(json.dumps(self.ip_relationships[str(addr)]))


if __name__ == '__main__':
    pcap = rdpcap('./demo.pcap')

    convo = ConvoHandler()

    for packet in pcap:
        convo.handle_packet(packet)
        try:
            convo.push_packet_as_single_stream()
        except Exception as e:
            print 'Bug: ', e
