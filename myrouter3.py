#!/usr/bin/env python

'''
Basic IPv4 router (static routing) in Python, stage 1.
'''

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
from srpy_common import log_info, log_debug, log_warn, SrpyShutdown, SrpyNoPackets, debugger

class Router(object):
    def __init__(self, net):
        self.queue = {}
        self.net = net
        self.forwardingTable = {}						    #creates dict var for forwarding table.
        self.ip_eth_dict = {}                               #creates dict var
        self.MACaddresses = {}                              #creates dict for MAC addresses. Key is IPAddress
        for intf in self.net.interfaces():                  #loop to go through interfaces 
            self.ip_eth_dict[intf.ipaddr] = intf.ethaddr    #adds IP addr (key) to eth addr (value)


    #checking that the ethernet address source = an IP address on router    
    def addr_check(self, header): 
        dst = header.protodst                               #set variable dst                     
        if dst in self.ip_eth_dict:                         #check to see if dst in addr dict
            return True                                     #good to go
        else:
            return False
        
    #creates reply
    def create_arp_reply(self, header,pkt):
        arp_reply = pktlib.arp()                            #creates an empty header to use to send reply
        arp_reply.opcode = pktlib.arp.REPLY                 #fills in opcode
        arp_reply.hwsrc = self.ip_eth_dict[header.protodst] #is mac addr connected to protodst from REQ
        arp_reply.hwdst = header.hwsrc                      #hwdst is hwsrc from REQ
        arp_reply.protosrc = header.protodst                #protosrc is dst from REQ
        arp_reply.protodst = header.protosrc                #protodst is src from REQ
        ether = ethernet()                                  #creates an ethernet packet
        ether.type  = ethernet.ARP_TYPE                     #NECESSARY??
        ether.src = arp_reply.hwsrc                         #SRC, is this right???
        ether.dst = pkt.src                                 #broadcasts message out...?
        ether.set_payload(arp_reply)                        #adds the payload which == None
        return ether

    #creates ethernet header to tack on and send IPv4 packet
    def create_eth_header(self, pkt, dstMAC, srcMAC):
        ether = ethernet()                                  #creates an ethernet packet
        ether.type  = ethernet.IP_TYPE                      #NECESSARY??
        ether.src = srcMAC                                  #SRC is own mac addr
        ether.dst = dstMAC                                  #MACaddress
        ether.set_payload(pkt.payload)                      #adds the payload which == None
        return ether    

    #create arp request
    def create_arp_request(self, header, packetObject, IPinfo, dstIP):
        arp_req = pktlib.arp()                                  #creates an empty header send request
        pkt = packetObject.pkt
        arp_req.opcode = pktlib.arp.REQUEST                     #fills in opcode
        interface = self.net.interface_by_name(IPinfo[2])       #get interface that will send on
        devIP = interface.ipaddr                                #gets IP
        devMAC = interface.ethaddr                              #MAC addr
        arp_req.hwsrc = devMAC                                  #is mac addr
        arp_req.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")            #hwdst is hwsrc from REQ
        arp_req.protosrc = devIP                                #protosrc is dst from REQ
        arp_req.protodst = dstIP                                #protodst is src from REQ       
        ether = ethernet()                                      #creates an ethernet packet
        ether.type  = ethernet.ARP_TYPE                         #NECESSARY??
        ether.src = devMAC                                      #SRC, is this right???
        ether.dst = EthAddr("ff:ff:ff:ff:ff:ff")                #broadcasts message out!
        ether.set_payload(arp_req)                              #adds the payload which == None
        packetObject.ARP_request = ether
        return ether

    #read file to populate forwarding table
    def readfile(self):
        #read the file
        file = open("forwarding_table3.txt", "r")
        for line in file:
            words = line.split(" ")
            words[3] = words[3].rstrip('\n')
            self.forwardingTable[IPAddr(words[0])] = [IPAddr(words[1]),IPAddr(words[2]),words[3]]

    #uses net.interfaces() and calls readfile 
    def interfaces(self):
        for intf in self.net.interfaces():
            ipaddr = intf.ipaddr
            netMask = intf.netmask
            netaddr = IPAddr(ipaddr.toUnsigned() & netMask.toUnsigned())
            self.forwardingTable[netaddr] = [netMask, None, intf.name]          #made this NONE!!!!!
 
    #checking if IPv4 destination IP address is in da forwarding table
    def in_forwarding_table(self, ip_header):
        bestKey = None
        bestPrefix = 0
        dstIP = ip_header.dstip
        for key in self.forwardingTable.keys():
            netmask = self.forwardingTable[key][0]
            result = IPAddr(dstIP.toUnsigned() & netmask.toUnsigned())
            if result == key:
                currentPrefix = netmask_to_cidr(netmask)
                if currentPrefix > bestPrefix:
                    bestPrefix = currentPrefix
                    bestKey = key
        return bestKey



    def router_main(self):
        self.readfile()
        self.interfaces()

        while True:
            try:
                dev,ts,pkt = self.net.recv_packet(timeout=1.0)
            except SrpyNoPackets:
                #log_debug("Timeout waiting for packets")
                toDel = []
                for key in self.queue:                                                          #iterate packetObjects in the queue
                    packetObject = self.queue[key]
                    if (time.time() - packetObject.lastSend) > 1:                                 
                        if packetObject.retries != 0:                                           #if retries are 0
                            packetObject.retries -= 1                                           #decrement retries by 1
                            self.net.send_packet(packetObject.dev, packetObject.ARP_request)
                            packetObject.lastSend = time.time()
                        else:   
                            toDel.append(key)
                            #NEW AF!
                            print "should send ICMP destination host unreachable error!"
            
                for item in toDel:
                    del self.queue[item]
                continue
            except SrpyShutdown:
                return
            print "packet arrived on:    ", dev
            #if ARP-packet (REQ or REPLY)------------------------------
            arp_header = pkt.find("arp")
            if arp_header != None:                                                  #checks if ARP-packet
                if arp_header.opcode == pktlib.arp.REQUEST:                         #checks if is an ARP request		
                    print addr_check()
                    if addr_check():                                                  #fvalid address
                        packet = self.create_arp_reply(arp_header, pkt)             #creates reply
                        self.net.send_packet(dev,packet)                            #sends reply
			print "JUST SENT ARP RESPONSE"

                elif arp_header.opcode == pktlib.arp.REPLY:                         #checks if is an ARP reply
                    dstIP = arp_header.protodst
                    interface = self.net.interface_by_name(dev)
                    devIP = interface.ipaddr
                    devMAC = interface.ethaddr
                    srcMAC = arp_header.hwsrc
                    srcIP = arp_header.protosrc

                    if dstIP == devIP:                                              #is this ARP reply meant for me
                        #create header forward packet on MACaddr just found
                        dstMAC = srcMAC                                             #flip because you now want to send it back
                        srcMAC = devMAC
                        self.MACaddresses[srcIP] = dstMAC                           #add newly MAC address to mac dictionary
                        packetObject = self.queue[srcIP]                            #temporarily store packet ]
                        pkt = packetObject.pkt
                        packet = self.create_eth_header(pkt, dstMAC, srcMAC)        #add ethernet header to packet
                        self.net.send_packet(dev,packet)                      
                        del self.queue[srcIP]                                       #delte packeet from queue                 

                else:
                    print "Error."                                                  #drop packet since not valid ARP-packet

            else:
                #if IPv4 packet----------------------------------
                ip_header = pkt.find("ipv4")
                if ip_header != None:                                                   #if IPv4packet! 
                    #AF NEW!
                    if ip_header.ttl == 0:                                               #AF: if TTL value is 0
                        print "ICMP time exceeded erro should be sent!"
                        break                                                           #AF: not sure this is correct! 
                    ip_header.ttl -= 1
                    dstIP = ip_header.dstip                                             #destination IP addr of IPheader
                    
                    #AF NEW!
                    srcIP = ip_header.srcip
                    interface = self.net.interface_by_name(dev)
                    devIP = interface.ipaddr 
                    print "WTF 1"
                    #packet sent to me-------------------------------------   
                    if dstIP == devIP:                                                      #if packet is for me
                        print "WTF 2"
                        #check if also ICMP echo request
                        #debugger()
                        icmp_header = pkt.find("icmp")
                        print "ICMP_header:   ", icmp_header
                        if icmp_header != None:
                            print "WTF 3"
                            oldPing = icmp_header.payload
                            #creat ICMP reply to send out
                            icmppkt = pktlib.icmp()                                                #create ICMP header
                            icmppkt.type = pktlib.TYPE_ECHO_REPLY
                            ping = pktlib.echo()
                            ping.id = oldPing.id 
                            ping.seq = oldPing.seq 

                            icmppkt.payload = ping
                 
                            #create IP header
                            ipreply = pktlib.ipv4()
                            ipreply.srcip = devIP
                            ipreply.dstip = srcIP
                            ipreply.ttl = 64
                            ipreply.payload = icmppkt
                            print "sending PING reply from:  ", ipreply.srcip
                            print "sending PING reply to:    ", ipreply.dstip

                            bestKey = self.in_forwarding_table(ipreply)
 
                            print "bestKey:    ", bestKey                           
                            #send back to place you just got from


                            if dstIP in self.MACaddresses:                  #if we know MAC address
                                #can send ping reply directly                                
                                print "YAY"
                            else:                                           # if we don't know MAC address
                                #need to get MAC address to send ping reply to
                                print "SHIT"
                                IPinfo = self.forwardingTable[bestKey]
                                print IPinfo
                                packetObject = packets()
                                packetObject.pkt = pkt
                                packetObject.ip_header = ip_header
                                packetObject.lastSend = time.time()
                                self.queue[dstIP] = packetObject 
                                print "dstIP:    ", srcIP
                                packetArp = self.create_arp_request(ip_header, packetObject, IPinfo, dstIP)   #creates packet 
                                dev = IPinfo[2]                                                     #dev is the interface to send o
                                print "dev sending out on:   ", dev
                                packetObject.dev = dev
                                print "packetObject:    ", packetObject
                                print "packet:     ", packetArp
                                self.net.send_packet(dev,packetArp)                                    #send request
                                print "packet sent!"
                            
                            """print "sending packet on:   ", dev
                            self.net.send_packet(dev,ipreply)
                            print "packet sent!"""

                    #print packet not sent to me------------------------------------------
                    else:                                                                   #if packet is not for me
                        bestKey = self.in_forwarding_table(ip_header)

                        if bestKey != None:                                                 #checks if a match in forwarding table
                            if self.forwardingTable[bestKey][1]==None:                      #checks if nextHop none-directly reachable
                                if dstIP in self.MACaddresses:                              #checks if already know MAC addr
                                    print "test 1"
                                    #send packet over that MAC address
                                    srcINTR = self.forwardingTable[bestKey][2]              #get own mac address with ^
                                    interface = self.net.interface_by_name(srcINTR)         #get own mac address
                                    srcMAC = interface.ethaddr
                                    dstMAC = self.MACaddresses[dstIP]                       #gets MACaddr for dstIP
                                    packet = self.create_eth_header(pkt, dstMAC, srcMAC)    #creates new packet to send
                                    dev = self.forwardingTable[bestKey][2]                  #gets net interface name for dstIP
                                    self.net.send_packet(dev,packet)                        #sends IPv4packet

                                else:                                                       #if don't know mac addr
                                    print "test 2"
                                    IPinfo = self.forwardingTable[bestKey]
                                    packetObject = packets()
                                    packetObject.pkt = pkt
                                    packetObject.ip_header = ip_header
                                    packetObject.lastSend = time.time()
                                    self.queue[dstIP] = packetObject 
                                    packet = self.create_arp_request(ip_header, packetObject, IPinfo, dstIP)   #creates packet 
                                    dev = IPinfo[2]                                                     #dev is the interface to send on

                                    packetObject.dev = dev
                                    print "WTF!"
                                    self.net.send_packet(dev,packet)                                    #send request
                                    print "sent ARP request to:    ", dstIP
                                                                              
                            else:                                                                       #if next HOP is not None
                                IPinfo = self.forwardingTable[bestKey]
                                nextHopIP = self.forwardingTable[bestKey][1]
                                nextHopDev = self.forwardingTable[bestKey][2]
                                if nextHopIP in self.MACaddresses:                                      #if already know MAC address
                                    print "test 3"
                                    #send packet over that MAC address
                                    srcINTR = self.forwardingTable[bestKey][2]                          #get own mac address with ^
                                    interface = self.net.interface_by_name(srcINTR)                     #get own mac address
                                    srcMAC = interface.ethaddr
                                    dstMAC = self.MACaddresses[dstIP]                                   #gets MACaddr for dstIP
                                    packet = self.create_eth_header(pkt, dstMAC, srcMAC)                #creates new packet to send
                                    dev = self.forwardingTable[bestKey][2]                              #gets netinterface name for dstIP
                                    self.net.send_packet(packetObject.dev, packetObject.ARP_request)    #sends IPv4packet 

                                   
                                else:                                                               #If don't know MAC address
                                    
                                    print "Test 4"
                                    packetObject = packets()
                                    packetObject.pkt = pkt
                                    packetObject.ip_header = ip_header
                                    packetObject.lastSend = time.time()
                                    self.queue[nextHopIP] = packetObject
                                    packet = self.create_arp_request(ip_header, packetObject, IPinfo, nextHopIP)   
                                    packetObject.dev = IPinfo[2]
                                    self.net.send_packet(packetObject.dev, packetObject.ARP_request)              #send request
               
                        else:                                                                       
                            #AF If not match in forwarding table
                            #send an ICMP destination network unreachable error
                            #should be sent back to the host referred to by the source address in the IP packet
                            print "ICMP destination network unreachable error should be sent!"
                            pass

                              
                
                    

def srpy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
    
class packets:
    def __init__(self):
        self.pkt = None
        self.ip_header = None
        self.macAddr  = 0           						 #creates dict var for forwarding table.
        self.retries = 5                                   #creates dict var
        self.ARP_request = None
        self.dev = None
        self.lastSend = None



