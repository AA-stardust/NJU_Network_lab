#!/usr/bin/env python3
'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time
import datetime

def cal_time(stamp1,stamp2):
    if stamp1>stamp2:
        return stamp1-stamp2
    else:
        return stamp2-stamp1

def learning(memory,input_port,src_mac):
    timestamp=time.time()
    memory[src_mac]=[input_port,timestamp]
    log_info("\nmy_momory: {}\n".format(memory))
    
def Flood_packet(net,my_interfaces,input_port,packet):
    for intf in my_interfaces:
        if input_port!=intf.name:
            log_info("Flooding packet {} to {}".format(packet,intf.name))
            net.send_packet(intf.name,packet)
            
def Transport_packet(net,my_interfaces,memory,input_port,packet):
    #log_info("\nTransprot log : {}\n".format(memory))
    eth=packet.get_header(Ethernet)
    mac_info=memory.get(eth.dst)
    if mac_info is None:
        Flood_packet(net,my_interfaces,input_port,packet)
    else:
        port=mac_info[0]
        log_info("Transport packet {} to {}".format(packet,port))
        net.send_packet(port,packet)
    
def time_decay(memory):
    t1=time.time()
    #log_info("local_time:{}".format(time.localtime(t1)))
    remove_list=[]
    for key,value in memory.items():
      t2=cal_time(t1,value[1])
      #log_info(" time_pass: {}".format(t2))
      if t2>10:
          remove_list.append(key)
    for key in remove_list:
        memory.pop(key)
        
def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    
    memory={}
    while True:
        try:
            #time_decay(memory)
            #if len(memory)==0 and count==0:
            #    log_info("\nNULL\nNull\n")
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return
        time_decay(memory)
        log_info("In {} received packet {} on {}".format(net.name, packet, input_port))
        eth=packet.get_header(Ethernet)
        
        #time_decay(memory)
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