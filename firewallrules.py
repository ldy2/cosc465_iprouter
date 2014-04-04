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
            print "PACKETTTT : ", pkt
            print type(pkt)
            if type(pkt) == type(pktlib.tcp()):
                print "HOORAY!!!!"
            if type(pkt) == type(pktlib.udp()):
                print "HOORAY FOR UDPPPPPPP!!!!"

            print "NETMASKKK:  ", ruleObject.netMask

            if (ruleObject.type == type(pkt)):

                if ruleObject.netMask != None:            
                    pktsrc =  IPAddr(ruleObject.netMask.toUnsigned() & pkt.srcip.toUnsigned())
                else:
                    pktsrc = pkt.srcip
                print "PKTSRCCCCCCCCCCCCC:  ", pktsrc
                
                if "/" in str(ruleObject.src):
                    templist = []
                    templist = ruleObject.src.split("/")
                    rulesrc = IPAddr(templist[0])
                    print "RULE SRCCCCCC:   ", type(rulesrc), rulesrc
                else:   
                    rulesrc = ruleObject.src 
                    print "RULE SRCCCCCC:   ", type(rulesrc), rulesrc

                '''
                    PROBLEM NOW IS HOW TO COMPARE THINGS
                    WHERE THE RULE SAYS ANY -- CURRENTLY
                    THATS SET TO 1 SO WE NEED TO FIGURE OUT 
                    HOW TO COMPARE!!

                '''

                if type(pkt) == type(pktlib.ipv4()) or type(pkt) == type(pktlib.icmp()):
                    print "SHOULD rEtuRn 11111111!!!!", (ruleObject.type == type(pkt))
                    conditional1 = (ruleObject.type == type(pkt)), (rulesrc == pktsrc), (ruleObject.dst == pkt.dstip)
                    print (ruleObject.type == type(pkt))
                    print (rulesrc == pktsrc)
                    print (ruleObject.dst == pkt.dstip)
                    print "OMG ITS THE END:::::::",  all(conditional1)  

                print "type(ruleObject.src):   ", type(ruleObject.src), ruleObject.src
                print "type(ruleObject.netMask):   ", type(ruleObject.netMask), ruleObject.netMask
                print "type(pktsrc):   ", type(pktsrc)
                print "PACKET TYPEEEEEEE:   ", type(pkt)
                print "ruleObject.dst:   ", type(ruleObject.dst), ruleObject.dst
                print type(pkt.dstip) #what's this supposed to be??
                print "Object srcport : ", type(ruleObject.srcport)
                print "PKT srcport : ", type(pkt.payload.srcport)
                print "Object dstport : ", type(ruleObject.dstport)
                print "PKT dstport : ", type(pkt.payload.dstport), pkt.payload.dstport

                if type(pkt) == type(pktlib.tcp()) or type(pkt) == type(pktlib.udp()):
                    print "SHOULD RetUrN 222222222!", (ruleObject.type == type(pkt))
                    conditional2 = (ruleObject.type == type(pkt)), (rulesrc == pktsrc), (ruleObject.dst == pkt.dstip), (int(ruleObject.srcport) == int(pkt.payload.srcport)), (int(ruleObject.dstport) == int(pkt.payload.dstport))
                    print "OMG ITS THE END:::::::", all(conditional2)
  
            
#testing!!
def tests():
    f = Firewall()
    ip = pktlib.ipv4()
    ip.srcip = IPAddr("172.16.42.1")
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


