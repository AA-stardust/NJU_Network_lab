#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *
cache_table={}
class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here


    def router_main(self):    
        
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        my_interfaces=self.net.interfaces()
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                #log_debug("Got a packet: {}".format(str(pkt)))
                log_info("\nIn {} received packet {} on {}\n".format(self.net.name, pkt, dev))
                arp=pkt.get_header(Arp)
                eth=pkt.get_header(Ethernet)
                if arp is None:
                    pass
                else:
                    cache_table[arp.senderprotoaddr]=arp.senderhwaddr
                    log_info("\ncache_table: {}\n".format(cache_table))
                    target_ip=arp.targetprotoaddr
                    my_ip=[]
                    for intf in my_interfaces:
                        if intf.ipaddr==target_ip:
                            new_pkt=create_ip_arp_reply(intf.ethaddr,eth.src,intf.ipaddr,arp.senderprotoaddr)
                            self.net.send_packet(dev,new_pkt)
                            break
                



def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
