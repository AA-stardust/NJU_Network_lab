#!/usr/bin/env python3
'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import sys
import time
LRU_LEN=5
def switch_table_get(dst_mac,memory):
    for i in memory:
        if i[0]==dst_mac:
            return i
    return None
def switch_table_get_i(dst_mac,memory):
    for i,j in enumerate(memory):
        if j[0]==dst_mac:
            return i
    return None
def switch_table_del(mac,memory):
    k=-1
    for i,j in enumerate(memory):
        if j[0]==mac:
            k=i
    if k==-1:
        return 
    else:
        del memory[k]
def switch_table_insert(port_info,memory):
    memory.insert(0,port_info)
    
def learning(memory,input_port,src_mac):
    port_info=switch_table_get(src_mac,memory)
    if port_info is None:#src_mac not in the table
        if len(memory)<LRU_LEN:#table not full, just add
            switch_table_insert([src_mac,input_port],memory)
        else:#table full,do something
            memory.pop()
            switch_table_insert([src_mac,input_port],memory)
    else:#src_mac is in the forwarding table
        if input_port==port_info[1]:#topology not changed do nothing
            return
        else:#topology changed , change the port, do not change the lru_info
            i=switch_table_get_i(src_mac,memory)
            memory[i][1]=input_port
    
    log_info("\nmy_momory: {}\n".format(memory))

def Flood_packet(net,my_interfaces,input_port,packet):
    for intf in my_interfaces:
        if input_port!=intf.name:
            log_info("Flooding packet {} to {}".format(packet,intf.name))
            net.send_packet(intf.name,packet)
            
def Transport_packet(net,my_interfaces,memory,input_port,packet):
    eth=packet.get_header(Ethernet)
    port_info=switch_table_get(eth.dst,memory)
    if port_info is None:#dst is not in table , flood
        Flood_packet(net,my_interfaces,input_port,packet)
    else:#dst in table ,update the time
        log_info("Transport packet {} to {}".format(packet,port_info[0]))
        switch_table_del(port_info[0],memory)
        switch_table_insert(port_info,memory)
        net.send_packet(port_info[1],packet)
        log_info("memory after transport: {}".format(memory))
    
def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    
    memory=[]
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
