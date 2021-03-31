from switchyard.lib.userlib import *
import time
import random
class SingleRule():
    def __init__(self, protocol, isPermit, src, dst, srcport=None, dstport=None, ratelimit=None, impair=False):
        self.protocol=protocol
        if isPermit=='permit':
            self.isPermit=True
        else:
            self.isPermit=False
        self.src=self.addr(src)
        self.dst=self.addr(dst)
        if srcport=='any' or srcport==None:
            self.srcPort=None
        else:
            self.srcPort=int(srcport)
        if dstport=='any' or dstport==None:
            self.dstPort=None
        else:
            self.dstPort=int(dstport)
        self.bucket=0
        if ratelimit != None:
            self.ratelimit=int(ratelimit)
            self.bucket=self.ratelimit
        else:
            self.ratelimit=None
        self.timestamp=time.time()
        self.impair=impair
    def add_tokens(self,timestamp):
        if self.ratelimit==None:
            return
        interval=timestamp-self.timestamp
        flag=False
        while interval>=0.5:
            flag=True
            interval-=0.5
            self.bucket+=self.ratelimit/2
            if self.bucket>self.ratelimit*2:
                self.bucket=self.ratelimit*2
                break
        if flag:
            print('after update: {}'.format(self.bucket))
            self.timestamp=time.time()
        else:
            print('no update ago time:{} now time:{}'.format(self.timestamp,timestamp))
        '''if self.ratelimit is not None:
            tokens=self.ratelimit/2
            if self.bucket+tokens<=self.ratelimit*2:
                self.bucket+=tokens
            else:
                self.bucket=self.ratelimit*2'''
    def addr(self,ipv4_addr):
        if ipv4_addr=='any':
            return IPv4Network('0.0.0.0/0')
        elif ipv4_addr.find('/')==-1:
            return IPv4Network(ipv4_addr,strict=False)
        else:
            return IPv4Network(ipv4_addr)

class RuleProcess():
    def __init__(self):
        RuleFile='./firewall_rules.txt'
        self.TextRule=[]
        self.rule=[]
        print('start read firewall_rules.txt')
        self.protocol={
            "ip": IPv4,
            "tcp": IPProtocol.TCP,
            "udp": IPProtocol.UDP,
            "icmp": IPProtocol.ICMP
        }
        with open(RuleFile) as rule:
            for line in rule:
                line=line.strip()
                if len(line)>0 and line[0]!='#':
                    self.TextRule.append(line)
        self.set_rule()
        #print('rule:{}'.format(self.rule))
    def set_rule(self):
        for rule in self.TextRule:
            rule=rule.split(' ')
            isPermit=rule[0]
            src=rule[rule.index('src')+1]
            dst=rule[rule.index('dst')+1]
            protocol=self.protocol[rule[1]]
            srcPort=None
            dstPort=None
            ratelimit=None
            impair=False
            if 'srcport' in rule:
                srcPort=rule[rule.index('srcport')+1]
            if 'dstport' in rule:
                dstPort=rule[rule.index('dstport')+1]
            if 'ratelimit' in rule:
                ratelimit=rule[rule.index('ratelimit')+1]
            if 'impair' in rule:
                impair=True
            self.rule.append(SingleRule(protocol,isPermit,src,dst,srcport=srcPort,dstport=dstPort,\
                                        ratelimit=ratelimit,impair=impair))
    def judge_permit(self,pkt):
        result=True
        if pkt.has_header(IPv4):
            print('analysis pkt with ipv4')
            ipv4=pkt.get_header(IPv4)

            for i,rule in enumerate(self.rule):
                #print('rule protocol:{}'.format(rule.protocol))
                if rule.protocol==IPv4 or ipv4.protocol==rule.protocol:
                    if ipv4.src in rule.src and ipv4.dst in rule.dst:
                        #print('pkt dst port:{} rule.dst port:{}'.format(pkt[2].src,rule.dstPort))
                        if (rule.srcPort is None or rule.srcPort == pkt[2].src) \
                                and (rule.dstPort is None or rule.dstPort == pkt[2].dst):
                            print('rule matched,rule:{},result:{}'.format(self.TextRule[i],rule.isPermit))

                            if rule.impair==True:
                                drop_rate=0.1
                                r=random.uniform(0,1)
                                if r<drop_rate:
                                    return False
                                else:
                                    return True#a rule with impair will use permit or it's not legal
                            if rule.ratelimit==None:
                                return rule.isPermit
                            rule.add_tokens(time.time())
                            length=len(pkt)-len(pkt.get_header(Ethernet))
                            print('cmp tokens: bucket:{} len:{}'.format(rule.bucket,length))
                            if rule.bucket>=length:
                                rule.bucket-=length
                                return True
                            else:
                                return False

        return result

    def add_tokens(self):
        for rule in self.rule:
            rule.add_tokens(time.time())
        '''print('after add tokens: ')
        for i,rule in enumerate(self.rule):
            if rule.ratelimit is not None:
                print('rule:{} tokens:{}'.format(self.TextRule[i],rule.bucket))'''
    def print_text_rule(self):
        for text in self.TextRule:
            print(text)

def main(net):
    # assumes that there are exactly 2 ports
    portnames = [ p.name for p in net.ports() ]
    portpair = dict(zip(portnames, portnames[::-1]))
    print('portpair:{}'.format(portpair))
    rule=RuleProcess()
    rule.print_text_rule()

    while True:
        pkt = None
        try:
            timestamp,input_port,pkt = net.recv_packet(timeout=0.5)
        except NoPackets:
            pass
        except Shutdown:
            break
        if pkt is not None:
            print('\nReceive a pkt :{}'.format(pkt))
            # This is logically where you'd include some  firewall
            # rule tests.  It currently just forwards the packet
            # out the other port, but depending on the firewall rules
            # the packet may be dropped or mutilated.
            IsPermit=rule.judge_permit(pkt)
            if IsPermit==True:
                net.send_packet(portpair[input_port], pkt)
            else:
                continue


            
    net.shutdown()
