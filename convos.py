import binascii
import hashlib
from scapy.all import *
from pkt import Packet
import logging
import json
import os

logging.basicConfig(level=logging.INFO)

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
        self.frag_counter = {}
        self.ip_relationships = {}

    def handle_packet(self, scapy_pkt):
        """
        Get packet flags/options and then act accordingly
        :param scapy_pkt: a packet object from scapy library
        """
        is_MPTCP = False
        self.pkt = Packet(scapy_pkt)
        tcp_opts = set(list(self.pkt.get_opts()))
        zero_len_opts = set(["FIN", "FINACK", "MPJOIN", "MPCAPABLE"])
        
        found_frag = None
        if not tcp_opts.intersection(zero_len_opts):
            found_frag = not self.pkt.frag_check()

        for opt in tcp_opts:
            if opt != 'DSS':
                logging.debug('MPTCP Subtype: {}'.format(opt))

            if "DSS" in opt:
                if hasattr(self.pkt, 'dsn'):
                    logging.debug('Attempting Update DSS for {} with {}, seq # {}'.format(self.pkt.addr, self.pkt.dsn, self.pkt.seq))
                    self.update_dss(self.pkt.addr, self.pkt.dsn, self.pkt.seq, frag=found_frag)

            if "FIN" in opt:
                logging.debug('Attempting Teardown {}'.format(self.pkt.addr))
                self.teardown(self.pkt.addr)

            if "FINACK" in opt:
                logging.debug('Attempting Teardown + End-Convo {}'.format(self.pkt.addr))
                self.teardown(self.pkt.addr, end_convo=True)

            if "MPCAPABLE" in opt:
                if hasattr(self.pkt, 'snd_key'):
                    snd_key = format(self.pkt.snd_key, 'x')
                    logging.debug('Attempting Add Master {} with key {}'.format(self.pkt.addr, snd_key))
                    self.add_master(self.pkt.addr, snd_key)

            if "MPJOIN" in opt:
                if hasattr(self.pkt, 'rcv_token'):
                    hextoken = format(self.pkt.rcv_token, 'x')
                    logging.debug('Attempting to add Subflow for {} with token {}'.format(self.pkt.addr, hextoken))
                    self.add_subflow(self.pkt.addr, hextoken)


    def add_frag(self, addr, count=1, limit=20, subflow=False):
        if subflow and addr in self.subflows.keys():
            addr = self.subflows[addr]['master']

        if addr in self.frag_counter.keys():
            self.frag_counter[addr] += 1

        else:
            self.frag_counter[addr] = 1

        if self.frag_counter[addr] > limit:
            logging.warn("Convo {} has exceeded fragmentation limit of {}.  Possible Fragmentation Attack".format(addr, limit))
        
        #from pprint import pprint
        #pprint(self.frag_counter)


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
            logging.error('Oh shit, we have a packet but no listed DSN for it! \n '
                         'Here\'s the adress sequence number for reference: \n '
                         'addr: {} \n seq: {}'.format(self.pkt.addr, self.pkt.seq))

        self.pkt.send()
        print self.pkt.pkt.summary()
        logging.info('Sent: {} -> {} seq {}'.format(self.pkt.pkt[TCP].sport, self.pkt.pkt[TCP].dport, self.pkt.seq))

    def add_master(self, addr, snd_key):
        """
        Add a new convo to the master_print opts if opts != 'DSS' flows dict (and derive token from key)
        :param addr:    tuple with (src, dst)
        :param snd_key: hex value of sender's key in packet
        """
        generic_addr = frozenset(addr)

        # If session was not terminated properly, init teardown
        if generic_addr in self.convos:
            logging.info('Attempting Impromptu Teardown + End-Convo {}'.format(self.pkt.addr))
            self.teardown(self.pkt.addr, end_convo=True)

        self.ip_relationships[str(addr)] = []
        self.convos.add(generic_addr)
        # Derive token from key
        # If odd len string, 0 pad it
        if len(snd_key) % 2:
            snd_key = '0' + snd_key
        snd_key = binascii.unhexlify(snd_key)
        token = hashlib.sha1(snd_key).hexdigest()[:8]
        self.master_flows[addr] = {
            'token': token
        }
        logging.info('Added Master Flow {} token {}'.format(addr, token))

    def add_subflow(self, addr, rcv_token):
        """
        Add a new convo to the subflows dict and find its master
        :param addr:  tuple (src, dst)
        :param token: receiver's token
        :return:
        """
        logging.info('Add Subflow: {}'.format(addr))
        generic_addr = frozenset(addr)
        self.convos.add(generic_addr)
        # Find matching recv_key
        for flow, info in self.master_flows.iteritems():
            if info['token'] == rcv_token:
                master_addr = flow[::-1]
                if master_addr in self.master_flows.keys():
                    self.ip_relationships[str(master_addr)].append(str(addr))
                    
                    # connection flood check
                    # TODO remove magic number
                    CONN_LIMIT = 10
                    if len(self.ip_relationships[str(master_addr)]) >= CONN_LIMIT:
                        logging.warn('Possible Connection Flood Detected')
                        # self.teardown(master_addr, end_convo=True)
                        logging.warn('Connection Limit Passed, {} will no longer be logged'.format(master_addr))
                        return "conn flood"
                                            
                    else:
                        self.subflows[addr] = {
                            'master': master_addr
                        }
                        logging.info('Added Subflow {} token {}'.format(addr, rcv_token))

                else:
                    logging.info('Orphan Subflow {}'.format(addr,master_addr))

    def update_dss(self, addr, dsn, seq_num, frag=False):
        # type: (list, int, int) -> None
        """
        Update a flows DSS map
        :param addr:    tuple (src, dst)
        :param dsn:     int packet dsn
        :param seq_num: int packet sequence number
        """

        generic_addr = frozenset(addr)
        if generic_addr in self.convos:
            dss_dict = {
                'dsn': dsn,
                'diff': dsn - seq_num #TODO examine if this is necessary (I don't think it is)
            }

            if addr in self.master_flows.keys():
                self.master_flows[addr].update(dss_dict)
                logging.debug('Updated Master {}'.format(addr))
                if frag:
                    self.add_frag(str(addr))

            elif addr in self.subflows.keys():
                self.subflows[addr].update(dss_dict)
                logging.debug('Updated Subflow {}'.format(addr))
                if frag:
                    self.add_frag(str(addr), subflow=True)

            logging.debug('Updated DSS: {} dsn {}'.format(addr, dsn))

        else:
            logging.debug("No record for flow {}".format(addr))
 

    def teardown(self, addr, end_convo=False):
        """
        Remove flow dict entry and optionally the convo frozenset entry
        :param addr: tuple (src, dst)
        :param end_convo: Used when a FINACK is given, remove convo frozenset entry
        """
        return
        generic_addr = frozenset(addr)
        if generic_addr in self.convos:
            if addr in self.master_flows:
                del self.master_flows[addr]
                self.export_ips(addr)
            elif addr in self.subflows:
                del self.subflows[addr]

            logging.info('Tore Down {}'.format(addr))

            if end_convo:
                print self.convos
                self.convos.remove(generic_addr)
                logging.info('End Convo {}'.format(addr))

    def export_ips(self, addr, file="ip_relationships.json"):
        if os.path.isfile(file):
            perms = 'a'
        else:
            perms = 'w+'

        with open(file, perms) as log_file:
            log_file.write(json.dumps(self.ip_relationships[str(addr)]))


if __name__ == '__main__':
    pcap = rdpcap('fragmenttest.pcap')
    convo = ConvoHandler()


    def handler(pkt):
        if TCP in pkt:
            if convo.handle_packet(pkt) == "conn flood":
                return
            try:
                convo.push_packet_as_single_stream()
            except Exception as e:
                print 'Bug: ', e

    sniff(iface="eno1", prn=handler, filter="tcp", store=0)


"""
for packet in pcap:
    if convo.handle_packet(packet) == "conn flood":
        continue # tripped security alarm, don't send packet
    try:
        convo.push_packet_as_single_stream()
    except Exception as e:
        print 'Bug: ', e
"""
 
