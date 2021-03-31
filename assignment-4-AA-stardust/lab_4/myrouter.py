#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *
from switchyard.lib.address import *
from switchyard.lib.packet import *
cache_table={}#ip: mac
forward_table=[]#[[net_addr,netmask,next_hop,port]]
arp_queue={}##ip: [waiting_pkt],time,num_of_arp,port
def cache_table_init(my_interfaces):
    for intf in my_interfaces:
        cache_table[intf.ipaddr]=intf.ethaddr
def forward_init(my_interfaces):
    file=open('forwarding_table.txt','r')
    line=file.readline()
    while line:
        if line[len(line)-1]=='\n':
            line=line[0:len(line)-1]
        line=line.split(' ')
        forward_table.append(line)
        line=file.readline() 
    for intf in my_interfaces:
        forward_table.append([str(intf.ipaddr),str(intf.netmask),None,intf.name])
def forward_match(destaddr):
    log_info('in forward_match: destaddr {}'.format(destaddr))
    len=0
    pos=0
    flag=False
    for i,item in enumerate(forward_table):
        net_ip,netmask,next_hop_ip,port=item
        s=str(net_ip)+"/"+str(netmask)
        netaddr=IPv4Network(s,strict=False)
        match= destaddr in netaddr
        if match==True:
            flag=True
            if len<netaddr.prefixlen:
                pos=i
                len=netaddr.prefixlen
    if flag==False:
        for i,item in enumerate(forward_table):
            net_ip,netmask,next_hop,port=item
            if next_hop is None:
                continue
            log_info('next_hop:{}\n'.format(next_hop))
            next_hop=IPv4Network(next_hop,strict=False)
            match=destaddr in next_hop
            if match==True:
                flag=True
                if len<next_hop.prefixlen:
                    pos=i
                    len=next_hop.prefixlen
                    
    log_info('format_match finished, pos: {} flag:{}\n'.format(pos,flag)) 
    if flag:
        return pos
    else:
        return None
    
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
        router_faces=[]
        for i in my_interfaces:
            router_faces.append([i.ipaddr,i.ethaddr,i.name])
        log_info('router_face:{}'.format(router_faces))
        router_ip=[]
        for intf in my_interfaces:
            router_ip.append(intf.ipaddr)
        forward_init(my_interfaces)
        log_info('forward_table: {}'.format(forward_table))
        cache_table_init(my_interfaces)
        log_info('cache_table:{}'.format(cache_table))
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
            
            for key in list(arp_queue.keys()):
                if time.time()-arp_queue[key][1]>1 and arp_queue[key][2]>=5:
                    log_info('delete arp_table\n')
                    del arp_queue[key]
                    log_info('arp_table_after_del:{}'.format(arp_queue))
            for key,item in arp_queue.items():
                if time.time()-item[1]>1:#send arp again
                    log_info('resend arp\n')
                    pkt_list,timestamp,arp_num,port,arpReq=item
                    self.net.send_packet(port,arpReq)
                    timestamp=time.time()
                    arp_num+=1
                    arp_queue[key]=[pkt_list,timestamp,arp_num,port,arpReq] 
                    log_info('arp_table_after_resend:{}'.format(arp_queue))
            if gotpkt:
                #log_debug("Got a packet: {}".format(str(pkt)))
                log_info("\nIn {} received packet {} on {}\n".format(self.net.name, pkt, dev))
                arp=pkt.get_header(Arp)
                eth=pkt.get_header(Ethernet)
                ipv4=pkt.get_header(IPv4)
                
                if pkt.has_header(Arp):

                    if arp.operation==ArpOperation.Request:
                        log_info('arp_request\n')  
                        cache_table[arp.senderprotoaddr]=arp.senderhwaddr
                        log_info("\ncache_table: {}\n".format(cache_table))
                        target_ip=arp.targetprotoaddr
                        my_ip=[]
                        for intf in my_interfaces:
                            if intf.ipaddr==target_ip:
                                new_pkt=create_ip_arp_reply(intf.ethaddr,eth.src,intf.ipaddr,arp.senderprotoaddr)
                                self.net.send_packet(dev,new_pkt)
                                break
                    elif arp.operation==ArpOperation.Reply:
                        log_info('arp_reply\n')
                        cache_table[arp.senderprotoaddr]=arp.senderhwaddr
                        log_info('reply_debug: arp.sender:{}\narp_key:{}\n'.format(arp.senderprotoaddr,arp_queue.keys()))
                        keys=[str(i) for i in arp_queue.keys()]
                        if (str(arp.senderprotoaddr) in keys):
                            log_info('arp_rpl_in\n'.format())
                            for waiting_pkt in arp_queue[str(arp.senderprotoaddr)][0]:
                                e=waiting_pkt.get_header(Ethernet)
                                e.dst=arp.senderhwaddr
                                e.src=self.net.interface_by_name(dev).ethaddr
                                new_pkt=e+waiting_pkt.get_header(IPv4)+waiting_pkt.get_header(ICMP)
                                self.net.send_packet(dev,new_pkt)
                            del arp_queue[str(arp.senderprotoaddr)]
                        log_info('reply_finished\n')
                                
                elif pkt.has_header(IPv4):
                    log_info('ipv4 recevied\n')
                    ipv4=pkt.get_header(IPv4)
                    ipv4.ttl-=1
                    if ipv4.dst in router_ip:
                        continue
                    pos=forward_match(ipv4.dst)
                    if pos==None:
                        continue
                    elif False:
                        continue
                    else:#获得最长匹配
                        if forward_table[pos][2]!=None:
                            curNextHop=forward_table[pos][2]
                        else:
                            curNextHop=ipv4.dst
                        if curNextHop in cache_table.keys():
                            log_info('ipv4 send directly\n')
                            eth=pkt.get_header(Ethernet)
                            eth.dst=cache_table[curNextHop]
                            eth.src=self.net.interface_by_name(forward_table[pos][3]).ethaddr
                            new_pkt=eth+pkt.get_header(IPv4)+pkt.get_header(ICMP)
                            log_info('forward_table_before_send: {}'.format(forward_table[pos]))
                            self.net.send_packet(forward_table[pos][3],new_pkt)
                            
                        else:#cache table中找不到相应的ip-mac，发送arp
                            log_info('ipv4 need arp\n')
                            log_info('forward_table_befroe_Request:{}'.format(forward_table[pos]))
                            if curNextHop in arp_queue.keys():
                                arp_queue[curNextHop][0].append(pkt)
                            arpReq=create_ip_arp_request(
                                self.net.interface_by_name(forward_table[pos][3]).ethaddr,
                                self.net.interface_by_name(forward_table[pos][3]).ipaddr,
                                curNextHop)
                            arp_queue[str(curNextHop)]=[[pkt],time.time(),1,forward_table[pos][3],arpReq]
                            self.net.send_packet(forward_table[pos][3],arpReq)
                            


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
