#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
from random import randint
import time
import random
def read_params():
    fp=open('middlebox_params.txt')
    r=fp.readline()
    r_list=r.split(' ')
    return float(r_list[1])
def get_seqNum(pkt,net):
    raw=pkt.get_header(RawPacketContents)
    seqNum=int.from_bytes(raw.data[:4],'big')
    return seqNum
def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    drop_rate=read_params()
    print('middlebox params drop rate:{}\n'.format(drop_rate))
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
        seqNum=0
        if gotpkt:
            log_debug("I got a packet {}".format(pkt))
            try:
                seqNum=get_seqNum(pkt,net)
            except:
                continue
            print('\ngot pkt:{}'.format(seqNum))
        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            r=random.random()
            print('random:{} '.format(r))
            if r<drop_rate:
                print('the packet was dropped')
                continue
            pkt[Ethernet].src='40:00:00:00:00:02'
            pkt[Ethernet].dst='20:00:00:00:00:01'
            net.send_packet("middlebox-eth1", pkt)
            print('send pkt: {} to middlebox-eth1'.format(seqNum))
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            pkt[Ethernet].src='40:00:00:00:00:01'
            pkt[Ethernet].dst='10:00:00:00:00:01'
            net.send_packet('middlebox-eth0',pkt)
            seqNum=get_seqNum(pkt,net)
            print('send pkt {} ack to middlebox-eth0'.format(seqNum))

        else:
            log_debug("Oops :))")

    net.shutdown()
