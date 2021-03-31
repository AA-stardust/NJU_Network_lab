#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time
import os

def read_params():
    fp=open('blaster_params.txt')
    r=fp.readline()
    if r[-1]=='\n':
        r=''.join(list(r)[0:-1])
    r_list=r.split(' ')
    blastee_ip=IPv4Address(r_list[1])
    num=int(r_list[3])
    length=int(r_list[5])
    sender_window=int(r_list[7])
    timeout=int(r_list[9])/1000
    recv_timeout=int(r_list[11])/1000
    return blastee_ip,num,length,sender_window,timeout,recv_timeout
class PktMsg():
    def __init__(self,pkt,seqNum):
        self.pkt=pkt
        self.seqNum=seqNum
        self.resendNum=0
        self.Ack=False
        self.resend=0

class Blaster(object):
    def __init__(self,net):
        self.net=net
        self.blaster_ip,self.num,self.length,self.sender_window,self.timeout,self.recv_timeout=read_params()
        print('\nparams: blaster_ip:{} num:{} payload_length:{} sender_window:{} timeout:{} recv_timeout:{}\n'.format(
              self.blaster_ip,self.num,self.length,self.sender_window,self.timeout,self.recv_timeout))
        self.middleEth=EthAddr('40:00:00:00:00:01')
        self.interface=self.net.interface_by_name('blaster-eth0')
        self.coarseTO=0
        self.window=[]
        self.window_send_time=time.time()
        self.LHS=0
        self.RHS=0
        self.total_send_pkt=0
        self.total_resend_pkt=0
        self.first_pkt_time=0
        self.last_ack_time=0
    def reset_time(self):
        self.window_send_time=time.time()
    def mk_udp(self,seqNum):
        eth=Ethernet()
        eth.src=self.interface.ethaddr
        eth.dst=self.middleEth
        ipv4=IPv4()
        ipv4.src=self.interface.ipaddr
        ipv4.dst=self.blaster_ip
        ipv4.protocol=IPProtocol.UDP
        udp=UDP()
        pkt=eth+ipv4+udp+seqNum.to_bytes(4,'big')+self.length.to_bytes(2,'big')+os.urandom(self.length)
        return pkt

    def resend(self):
        if len(self.window)==0:
            print('\nwindow if empty\n')
            return False
        #print('\nstart resend\n')
        curtime=time.time()
        is_resend = False
        if curtime-self.window_send_time>self.timeout:
            self.coarseTO+=1
            print('pkt resend: ',end=' ')
            for i,item in enumerate(self.window):
                if item.Ack==False:
                    item.resendNum+=1
                    self.net.send_packet(self.interface.name,item.pkt)
                    print('{}'.format(i+self.LHS),end=' ')
                    self.total_resend_pkt+=1
                    self.total_send_pkt+=1
                    is_resend=True
                    #break
            if is_resend:
                self.window_send_time=time.time()
            print('')
        #print('resend finished\n')
        return is_resend
    def print_window(self):
        print('window: ')
        for i,item in enumerate(self.window):
            print('{}:'.format(self.LHS+i),end=' ')
            if self.window[i].Ack==True:
                print('ack',end=' ')
            else:
                print('false',end=' ')
        print('')
    def can_send(self):
        if self.RHS>=self.num or self.RHS-self.LHS>=self.sender_window:
            return False
        return True
    def send_pkt(self):
        if self.RHS>=self.num or self.RHS-self.LHS>=self.sender_window:
            #print('\ncannot send pkt now!\n')
            return
        if self.RHS==0:
            self.first_pkt_time=time.time()
            print('first_pkt_time:{}'.format(self.first_pkt_time))
        seqNum=self.RHS
        self.RHS+=1
        pkt=self.mk_udp(seqNum)
        pkt_msg=PktMsg(pkt,seqNum)
        self.window.append(pkt_msg)
        print('\nready to send pkt:{}\n'.format(seqNum))
        self.net.send_packet(self.interface.name,pkt)
        self.total_send_pkt+=1
        self.print_window()
    def recv_pkt(self,pkt):
        print('in recv_pkt')
        row=pkt.get_header(RawPacketContents)
        seqNum=int.from_bytes(row.data[:4],'big')
        print('ack seqNum:{}'.format(seqNum))

        pos=seqNum-self.LHS
        if pos<0 or pos>=len(self.window):
            print('seqnum out of range!\n')
            print('sequm:{} LHS:{}'.format(seqNum,self.LHS))
            return
        else:
            self.window[pos].Ack=True
            if seqNum==self.num-1:
                self.last_ack_time=time.time()
                print('last_ack_time:{}'.format(self.last_ack_time))
            print('set seqNum ack is true')
            flag=False
            while len(self.window) > 0 and self.window[0].Ack == True:
                self.LHS += 1
                del self.window[0]
                flag=True
            if flag:
                self.reset_time()
            self.print_window()
    def print_stat(self):
         print('\nall the stats\n')
         total_tx_time=self.last_ack_time-self.first_pkt_time
         send_num=self.total_send_pkt-self.total_resend_pkt
         print('Total TX time:{}(seconds)'.format(total_tx_time))
         print('Number of reTx:{}'.format(self.total_resend_pkt))
         print('Total Coarse timeouts:{}'.format(self.coarseTO))
         print('Throughput(Bps):{}'.format(self.total_send_pkt*self.length/total_tx_time))
         print('Goodput: {}'.format(send_num*self.length/total_tx_time))
    def check(self):
        if self.RHS==self.LHS and self.RHS>=self.num:
            return True
        return False
    def get_recv_timeout(self):
        return self.recv_timeout
def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    blaster=Blaster(net)
    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp,dev,pkt = net.recv_packet(timeout=blaster.get_recv_timeout())
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False

            log_debug("Got shutdown signal")

        if gotpkt:
            log_info("I got a packet")
            blaster.recv_pkt(pkt)
            if blaster.check()==True:
                blaster.print_stat()
                return

        else:
            log_debug("Didn't receive anything")

            '''
            Creating the headers for the packet
            '''
            pkt = Ethernet() + IPv4() + UDP()
            pkt[1].protocol = IPProtocol.UDP

            '''
            Do other things here and send packet
            '''
        result=blaster.resend()
        if blaster.can_send():
            blaster.send_pkt()
    net.shutdown()
