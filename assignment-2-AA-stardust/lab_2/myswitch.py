#!/usr/bin/env python3
'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

def learning(memory,input_port,src_mac):
    memory[src_mac]=input_port
    log_info("\nmy_momory: {}\n".format(memory))

def Flood_packet(net,my_interfaces,input_port,packet):
    for intf in my_interfaces:
        if input_port!=intf.name:
            log_info("Flooding packet {} to {}".format(packet,intf.name))
            net.send_packet(intf.name,packet)
            
def Transport_packet(net,my_interfaces,memory,input_port,packet):
    eth=packet.get_header(Ethernet)
    port=memory.get(eth.dst)
    if port is None:
        Flood_packet(net,my_interfaces,input_port,packet)
    else:
        log_info("Transport packet {} to {}".format(packet,port))
        net.send_packet(port,packet)
    
def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    
    memory={}
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_info("In {} received packet {} on {}".format(net.name, packet, input_port))
        eth=packet.get_header(Ethernet)
        
        learning(memory,input_port,eth.src)
        
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            continue
        if eth.dst in mymacs:
            log_info("Packet intended for me")
        else:
            Transport_packet(net,my_interfaces,memory,input_port,packet)
            
        
        #log_info("\nljk\n{}\nljk\n".format(packet))
        '''if packet[0].dst in mymacs:
            log_info ("Packet intended for me")
        else:
            for intf in my_interfaces:
                if input_port != intf.name:
                    log_info ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)'''
    net.shutdown()
