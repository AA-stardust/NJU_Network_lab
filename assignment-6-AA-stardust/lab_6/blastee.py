#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time
import base64
def mk_udp(eth_src,eth_dst,ip_src,ip_dst,seqNum,payload_byte):
    eth=Ethernet()
    eth.src=eth_src
    eth.dst=eth_dst
    ipv4=IPv4()
    ipv4.src=ip_src
    ipv4.dst=ip_dst
    ipv4.protocol=IPProtocol.UDP
    udp=UDP()
    pkt=eth+ipv4+udp+seqNum.to_bytes(4,'big')+payload_byte
    return pkt

def read_params():
    fp=open('blastee_params.txt')
    r=fp.readline()
    if r[-1]=='\n':
        r=''.join(list(r)[0:-1])
    r_list=r.split(' ')
    print(r_list)
    print('\nblastee params fuction result: ip:{} num:{}\n'.format(IPv4Address(r_list[1]),int(r_list[3])))
    return IPv4Address(r_list[1]),int(r_list[3])

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    blastee=net.interface_by_name('blastee-eth0')
    blaster_ip,num_pkt=read_params()
    middleEth=EthAddr('40:00:00:00:00:02')
    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_info("I got a packet from {}".format(dev))
            log_info("Pkt: {}".format(pkt))
            if pkt.has_header(IPv4)==False or pkt.has_header(UDP)==False:
                continue
            ori=pkt.get_header(RawPacketContents)
            seqNum=int.from_bytes(ori.data[:4],'big')
            payload=base64.b64decode(base64.b64encode(ori.data[6:]))
            payload_byte=ori.data[6:]
            if len(payload_byte)<8:
                payload_byte+='\0'.encode()*(8-len(payload_byte))
            payload_byte=payload_byte[0:8]
            print('\nseqNum:{}\n'.format(seqNum))
            Ack=mk_udp(blastee.ethaddr,middleEth,blastee.ipaddr,blaster_ip,seqNum,payload_byte)
            print('\nblastee ready to send Ack:{}\n'.format(Ack))
            net.send_packet('blastee-eth0',Ack)
    net.shutdown()
