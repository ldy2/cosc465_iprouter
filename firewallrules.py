#!/usr/bin/env python

import sys
import os
import os.path
import time
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,IP_ANY
from pox.lib.packet import arp
from pox.lib.addresses import EthAddr,IPAddr,netmask_to_cidr, cidr_to_netmask, parse_cidr
#from srpy_common import log_info, log_debug, log_warn, SrpyShutdown, SrpyNoPackets, debugger


class Rules(object):
    def __init__(self):
        
        self.line = None
        self.action = None

        self.type = None  
        self.src = None
        self.srcport = None
        self.dst = None
        self.dstport = None
        self.ratelimit = None

        self.netMask = None
        self.bucket = 0


class Firewall(object):
    def __init__(self):
        self.rules = []
        pass

    #opens txt files and stores all rules in a list 
    def import_rules(self):
        file = open("firewall_rules.txt", "r")
        for line in file:
            if len(line) != 1:                  #this is to get rid of the empty lines
                words = []
                words = line.split()
                if words[0] == "permit" or words[0] == "deny":          #make sure it is not a comment
                    ruleObject = Rules()
                    ruleObject.line = line
                    for idx in range(len(words)):
                        if words[idx] == "permit":
                            ruleObject.action = "permit"
                        if words[idx] == "deny":
                            ruleObject.action = "deny"
                        if words[idx] == "ip":
                            ruleObject.type = type(pktlib.ipv4())
                        if words[idx] == "tcp":
                            ruleObject.type = type(pktlib.tcp())
                        if words[idx] == "udp":
                            ruleObject.type = type(pktlib.udp())
                        if words[idx] == "icmp":
                            ruleObject.type = type(pktlib.icmp())
                        if words[idx] == "src":
                            if words[idx+1] == "any":
                                ruleObject.src = 1
                            else:
                                ruleObject.src = words[idx+1]
                                if "/" in ruleObject.src:               #meaning its a net addr-we need the netmask
                                    temp = parse_cidr(ruleObject.src)
                                    srcnetMask = cidr_to_netmask(temp[1])
                                    ruleObject.netMask = srcnetMask
                        if words[idx] == "srcport":
                            if words[idx+1] == "any":
                                ruleObject.srcport = 1
                            else:
                                ruleObject.srcport = words[idx+1]
                        if words[idx] == "dst":
                            if words[idx+1] == "any":
                                ruleObject.dst = 1
                            else:
                                ruleObject.dst = words[idx+1]
                        if words[idx] == "dstport":
                            if words[idx+1] == "any":
                                ruleObject.dstport = 1
                            else:
                                ruleObject.dstport = words[idx+1]
                        if words[idx] == "ratelimit":
                            ruleObject.ratelimit = words[idx+1]

                    self.rules.append(ruleObject)

  
    def networkMatch(self, ruleObject, pkt):
        if (ruleObject.type == type(pkt)):
            if ruleObject.netMask != None:            
                pktsrc =  IPAddr(ruleObject.netMask.toUnsigned() & pkt.srcip.toUnsigned())
            else:
                pktsrc = pkt.srcip
            #checks if it is a network address or not
            if "/" in str(ruleObject.src):
                templist = []
                templist = ruleObject.src.split("/")
                rulesrc = IPAddr(templist[0])
            else:   
                rulesrc = ruleObject.src

            if "/" in str(ruleObject.dst):
                templist = []
                templist = ruleObject.dst.split("/")
                ruledst = IPAddr(templist[0])
            else:   
                ruledst = ruleObject.dst 

            #first type: ipv4/icmp
            if type(pkt) == type(pktlib.ipv4()) or type(pkt) == type(pktlib.icmp()):
                conditional1 = (ruleObject.type == type(pkt)), (rulesrc == pktsrc or rulesrc == 1), (ruledst == pkt.dstip or ruledst == 1)
                if ruleObject.ratelimit != None:

                    conditional1a = (ruleObject.type == type(pkt)), (rulesrc == pktsrc or rulesrc == 1), (ruledst == pkt.dstip or ruledst == 1), (ruleObject.bucket >= len(pkt.pack()))
                    return all(conditional1a)
                else:                    
                    return  all(conditional1)   
          
            #second type: udp/tcp
            if type(pkt) == type(pktlib.tcp()) or type(pkt) == type(pktlib.udp()):
                conditional2 = (ruleObject.type == type(pkt)), (rulesrc == pktsrc or rulesrc == 1), ((ruledst == 1) or (ruledst == pkt.dstip)), (int(ruleObject.srcport) == int(pkt.payload.srcport) or int(ruleObject.srcport) == 1), (int(ruleObject.dstport) == int(pkt.payload.dstport) or int(ruleObject.dstport) == 1)
          
                if ruleObject.ratelimit != None:
                    conditional2a = (ruleObject.type == type(pkt)), (rulesrc == pktsrc or rulesrc == 1), (ruledst == pkt.dstip or ruledst ==1), (int(ruleObject.srcport) == int(pkt.payload.srcport) or int(ruleObject.srcport) == 1), (int(ruleObject.dstport) == int(pkt.payload.dstport) or int(ruleObject.dstport) == 1), (ruleObject.bucket >= len(pkt.pack()))
                    return all(conditional2a)
                else:
                    return all(conditional2)


    def update_token_buckets(self):
        for i in range(0,len(self.rules)):
            ruleObject = self.rules[i]
            if ruleObject.ratelimit != None:
                #some manipulation of the net.recv_packet() timeout value which I don't understand
                ruleObject.bucket += (int(ruleObject.ratelimit)/2)


    def allow(self, pkt):  #I don't know how to do the actions on the packets -- it tests correctly but then what?
        #self.import_rules()
        for i in range(0,len(self.rules)):
            ruleObject = self.rules[i]
            result = self.networkMatch(ruleObject, pkt)
            if result == True and ruleObject.action == "deny":
                return False 
        return True

#testing!!
def tests():
    f = Firewall()
    ip = pktlib.tcp()
    ip.srcip = IPAddr("172.16.42.42")
    ip.dstip = IPAddr("192.128.42.42")
    ip.protocol = 17
    xudp = pktlib.udp()
    xudp.srcport = 80
    xudp.dstport = 53
    xudp.payload = "Hello, world"
    xudp.len = 8 + len(xudp.payload)
    ip.payload = xudp

    print len(ip) # print the length of the packet, just for fun

    assert(f.allow(ip) == True)

    time.sleep(0.5)
    f.update_token_buckets()

if __name__ == '__main__':
    tests()


