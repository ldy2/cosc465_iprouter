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
        self.line = 1
        self.src = 1
        self.srcPort = 1
        self.bucket = 1
        self.type = 1
        self.yes = 1
        self.netMask = 1
        self.dst = 1
        self.dstPort = 1
        self.bucket = None 

class Firewall(object):
    def __init__(self):
        self.rules = []
        pass


    #opens txt files and stores all rules in a list 
    def import_rules(self):
        file = open("firewall_rules.txt", "r")
        for line in file:
            #print "line:    ", line
            #print len(line)
            if len(line) != 1:                  #this is to get rid of the empty lines...need to come up with something more clever
                words = []
                words = line.split()
                print "words[0]:    ", words[0]
                if words[0] == "permit" or words[0] == "deny":          #make sure it is not a comment
                    print "poop"
                    ruleObject = Rules()
                    ruleObject.line = line
                    #ruleObject.src = line[4]
                    self.rules.append(ruleObject) #append object instead of line

        print "itterated through"
        #I'm hard coding this because I don't know what else to do
        ruleObject = self.rules[0]
        line = ruleObject.line
        print "line:   ", line
        words = []
        words = line.split()

        #create netmask
        print "line[4]:    ", words[3]
        print type(words[3])
        temp = parse_cidr(words[3])
        print "srcNetwork:   ", temp
        srcnetMask = cidr_to_netmask(temp[1])
        print "netMask:   ", srcnetMask
        ruleObject.netMask = srcnetMask
        ruleObject.src = temp[0]
        ruleObject.type = words[1]
        ruleObject.yes = words[0]
        print "finished importing"


        #MORE HARDCODING
        ruleObject = self.rules[1]
        line = ruleObject.line
        print "line:   ", line
        words = []
        words = line.split()

        #create netmask
        print "line[4]:    ", words[3]
        print type(words[3])
        ruleObject.src = temp[0]
        ruleObject.type = words[1]
        ruleObject.yes = words[0]
        ruleObject.srcPort = words[5]
        print "finished importing"


        #THIRD RULE HARDCODING
        ruleObject = self.rules[2]
        line = ruleObject.line
        print "line:   ", line
        words = []
        words = line.split()

        #create netmask
        print "line[4]:    ", words[3]
        print type(words[3])
        ruleObject.src = temp[0]
        ruleObject.type = words[1]
        ruleObject.yes = words[0]
        ruleObject.dstPort = words[9]
        ruleObject.dst = words[7]
        print "ruleObject.dst:    ", ruleObject.dst
        print "finished importing"



    #drop everything from a network that we don't trust
    def bad(self):
        pass
        #deny ip src 192.168.42.0/24 dst any
 
        #if network == self.rules[0][3]
        #src_ip = #need to get src IP from packet

        #boolean = self.networkMatch(srcIP, network)
        


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
        #ip_header = pkt.find("ipv4")
        
        self.import_rules()

        #for each rule, check the tcp or udp, src, dst, port,....
        #if all are correct, move on
        print "pkt.srcport:    ", pkt.payload.srcport
        for i in range(0,len(self.rules)):
            ruleObject = self.rules[i]
            print ruleObject.line
            #print packet.srcip
            #print ruleObject.src
            
            #print "ruleObject.src:   ", ruleObject.src


            #check type

            print pkt.payload


            if ruleObject.type != 1:
                if (ruleObject.type == "x"):
                    print "HELL YA"
            

            #check IP src
            if ruleObject.netMask != 1:
                print ruleObject.netMask
        
                temp =  IPAddr(ruleObject.netMask.toUnsigned() & pkt.srcip.toUnsigned())
                if (ruleObject.src == temp):
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
                if (int(ruleObject.srcPort) == int(pkt.payload.srcport)):      #not sure why we have to typcast
                    print "OMFG"
            
            

            

            #need to check if permit or deny

            #needs to be something like:
            #all(ruleObject.src == packet.src)(ruleObject.dst == packet.dst)(ruleObject.type = packet.type
def tests():
    print "YAY!!!!!!!!"
    f = Firewall()

    ip = pktlib.ipv4()
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

    # you can name this method what ever you like, but you'll
    # need some method that gets periodically invoked for updating
    # token bucket state for any rules with rate limits
    #f.update_token_buckets()

    # again, you can name your "checker" as you want, but the
    # idea here is that we call some method on the firewall to
    # test whether a given packet should be permitted or denied.
    assert(f.allow(ip) == True)

    # if you want to simulate a time delay and updating token buckets,
    # you can just call time.sleep and then update the buckets.
    time.sleep(0.5)
    f.update_token_buckets()

if __name__ == '__main__':
    # only call tests() if this file gets invoked directly,
    # not if it is imported.
    tests()




#rule class -- match method (does rule match packet?)
#   - also go based on token bucket?

#class
