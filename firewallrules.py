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
        self.bucket = None
        
        self.yes = None  #I don't know what this is and don't use it anywhere
        

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
                            ruleObject.type = "ip"
                        if words[idx] == "tcp":
                            ruleObject.type = "tcp"
                        if words[idx] == "udp":
                            ruleObject.type = "udp"
                        if words[idx] == "icmp":
                            ruleObject.type = "icmp"
                        if words[idx] == "src":
                            ruleObject.src = words[idx+1]
                            if "/" in ruleObject.src:               #meaning its a net addr-we need the netmask
                                temp = parse_cidr(ruleObject.src)
                                srcnetMask = cidr_to_netmask(temp[1])
                                ruleObject.netMask = srcnetMask
                        if words[idx] == "srcport":
                            ruleObject.srcport = words[idx+1]
                        if words[idx] == "dst":
                            ruleObject.dst = words[idx+1]
                        if words[idx] == "dstport":
                            ruleObject.dstport = words[idx+1]
                        if words[idx] == "ratelimit":
                            ruleObject.ratelimit = words[idx+1]

                    print #we can delete this once its all working
                    print "************RULE OBJECT****************"  
                    print ruleObject.line
                    print ruleObject.action
                    print ruleObject.type
                    print ruleObject.src                    
                    print ruleObject.srcport
                    print ruleObject.dst
                    print ruleObject.dstport
                    print ruleObject.netMask
                    print ruleObject.ratelimit
                    print
                   
                    self.rules.append(ruleObject)

    def networkMatch(self, ip, network):
        netMask = cidr_to_netmask(network.toUnsigned()) #should create netMask
        result = IPAddr(ip.toUnsigned() & netmask.toUnsigned())
        if result == network:
            return True
        else:
            return False

    def allow(self, pkt):
        print "ALLOW"
        print "packet:    ", pkt

        self.import_rules()

        #for each rule, check the type, src, dst, port,....
        #if all are correct, move on
        print "pkt.srcport:    ", pkt.payload.srcport
        for i in range(0,len(self.rules)):
            ruleObject = self.rules[i]
            print "CURRENT RULE-------------", ruleObject.line
            print "Payload : ", pkt.payload

            '''
            check if ip/tcp/udp/icmp then check fields accordingly --
            then do an all (one)(two)...
            the all will only return True if all conditionals are true

            I THINK THE FEW LINES BELOW ARE ALL WE NEED...
            as soon as we can figure out what type the packets are
            '''

            #pktsrc =  IPAddr(ruleObject.netMask.toUnsigned() & pkt.srcip.toUnsigned())
            #if ip or icmp packet:
                #return all(ruleObject.src == pktsrc, ruleObject.dst == pkt.dstip)  

            #if tcp or udp packet:
                #return all(ruleObject.src == pktsrc, ruleObject.dst == packet.dst, int(ruleObject.srcport) == int(pkt.payload.srcport), int(ruleObject.dstport) == int(pkt.payload.dstport))
    
            if ruleObject.type != 1:
                if (ruleObject.type == "x"):
                    print "HELL YA"

            #check IP src
            if ruleObject.netMask != 1:
                print ruleObject.netMask
        
                pktsrc =  IPAddr(ruleObject.netMask.toUnsigned() & pkt.srcip.toUnsigned())
                if (ruleObject.src == pktsrc):
                    print "SHOULD DENY THIS PACKET BECAUSE IT CAME FROM BANNED NETWORK"
           
            #check IP dst
            if ruleObject.dst != 1:
                print "yay"
                print "ruleObject.dst:   ", ruleObject.dst
                print "pkt.dstip:   ", pkt.dstip              
                if (ruleObject.dst == pkt.dstip):
                    print "MOTHER FUCKER!!!"                

            #check SRC port
            if ruleObject.srcPort != 1:
                print "HERE!!!!!"
                print "ruleObject.port:   ", ruleObject.srcPort
                print "pkt.payload.scrport:   ", pkt.payload.srcport
                if (int(ruleObject.srcPort) == int(pkt.payload.srcport)):      #not sure why we have to typcast
                    print "OMFG"
            
            #check DST port
            if ruleObject.dstPort != 1:
                print "HERE!!!!!"
                print "ruleObject.port:   ", ruleObject.srcPort
                print "pkt.payload.scrport:   ", pkt.payload.srcport
                if (int(ruleObject.dstport) == int(pkt.payload.dstport)):      #not sure why we have to typcast
                    print "OMFG"

            #need to check if permit or deny

            #all will return true if all the conditionals are true
            #all(ruleObject.src == pktsrc, ruleObject.dst == packet.dst, int(ruleObject.srcport) == int(pkt.payload.srcport), int(ruleObject.dstport) == int(pkt.payload.dstport))


#testing!!
def tests():
    f = Firewall()
    ip = pktlib.tcp()
    ip.srcip = IPAddr("192.168.42.1")
    ip.dstip = IPAddr("172.16.42.42")
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

