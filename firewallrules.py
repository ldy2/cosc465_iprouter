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
from pox.lib.addresses import EthAddr,IPAddr,netmask_to_cidr
#from srpy_common import log_info, log_debug, log_warn, SrpyShutdown, SrpyNoPackets, debugger


class Firewall(object):
    def __init__(self):
        self.rules = []


    #opens txt files and stores all rules in a list 
    def import_rules(self):
        file = open("firewall_rules.txt", "r")
        for line in file:
            if line[0] == "permit" | line[0] == "deny":
                self.rules.append(line) #append object instead of line

    #drop everything from a network that we don't trust
    #def bad(self):
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


    def allow(self, packet):
        print "ALLOW"
        print "packet:    ", packet
        import_rules()

def tests():
    print "YAY!!!!!!!!"
    f = Firewall()

    ip = pktlib.ipv4()
    ip.srcip = IPAddr("172.16.42.1")
    ip.dstip = IPAddr("10.0.0.2")
    ip.protocol = 17
    xudp = pktlib.udp()
    xudp.srcport = 53
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

