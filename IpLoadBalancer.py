
####################################################
#
#	File Name : IpLoadBalancer
#
#	author    : Ramprasad Tamilselvan
#
###################################################

from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random

# timeout constants for of messages
IDLE_TIMEOUT = 50
HARD_TIMEOUT = 0

class IpLoadBalancer(object):

    # initialize
    def __init__(self, service_ip, server_ips = []):
        core.openflow.addListeners(self)
        self.serviceIp = service_ip
        self.serverIp = server_ips
        self.mac_table = {}
        self.serverDetails = {}
        self.mac_to_port = {}

    # new switch connection
    def _handle_ConnectionUp(self, event): 
        # fake mac id for service ip
        self.lb_mac = EthAddr("0A:00:00:00:00:01")
        self.connection = event.connection

        # pre emptively collecting the mac and port number of server IPs
        # by sending ARP request packets
        for ip in self.serverIp:

            # constructing ARP packet
            arpPacket = arp()
            arpPacket.opcode = arpPacket.REQUEST
            arpPacket.hwsrc = self.lb_mac
            arpPacket.hwdst = ETHER_BROADCAST
            arpPacket.protosrc = self.serviceIp
            arpPacket.protodst = ip
          
            # constructing ethernet packet with ARP as payload
            e = ethernet(type = ethernet.ARP_TYPE, src = self.connection.eth_addr, dst = ETHER_BROADCAST)
            e.set_payload(arpPacket)

            # constructing openflow out message
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.in_port = of.OFPP_NONE

            # sending message
            self.connection.send(msg)
    
    # sending ARP replies for the request with service IP      
    def sendProxyArpReply(self, event, packet):

        log.info("Sending proxy ARP reply to IP = %s" %packet.protosrc)
        # constructing ARP packet
        arpPacket = arp()
        arpPacket.opcode = arpPacket.REPLY
        arpPacket.hwsrc = self.lb_mac
        arpPacket.hwdst = packet.hwsrc
        arpPacket.protosrc = self.serviceIp
        arpPacket.protodst = packet.protosrc
        
        # constructing ethernet packet
        e = ethernet(type = ethernet.ARP_TYPE, src = self.connection.eth_addr, dst = ETHER_BROADCAST)
        e.set_payload(arpPacket)

        # constructing openflow out message
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = event.port

        # sending message
        self.connection.send(msg)
    
    # updates MAC and port for the corresponding server IP
    def updateServerDetails(self, inPort, serverMac, serverIp):
        log.info("Updating MAC and Port for IP = %s" %serverIp)
        tempList = [serverMac, inPort]
        self.serverDetails[serverIp] =  tempList

    # Installs the flow in switch for communication from server to client
    def installFlowFromServer(self, event, packet, serverIp):

        log.info("Installing flow from server: server IP = %s  client IP = %s" %(serverIp, packet.next.srcip))

        # constructing open flow message
        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = HARD_TIMEOUT
        msg.buffer_id = None

        # matching criterias are defined
        msg.match.in_port = self.serverDetails[serverIp][1]
        msg.match.dl_src = self.serverDetails[serverIp][0]
        msg.match.dl_dst = packet.src
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_src = serverIp
        msg.match.nw_dst = packet.next.srcip
        
        # actions to be done are defined
        msg.actions.append(of.ofp_action_nw_addr.set_src(self.serviceIp))
        msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        msg.actions.append(of.ofp_action_output(port = event.port))
     
        # sending message
        self.connection.send(msg)

    def installFlowFromClient(self, event, packet, serverIp):

        log.info("Installing flow from client: server IP = %s  client IP = %s" %(serverIp, packet.next.srcip))
        # constructing open flow message
        msg = of.ofp_flow_mod()
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = HARD_TIMEOUT
        msg.buffer_id = None
        msg.data = event.ofp

        # matching criterias are defined
        msg.match.in_port = event.port
        msg.match.dl_src = packet.src
        msg.match.dl_dst = self.lb_mac
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_src = packet.next.srcip
        msg.match.nw_dst = self.serviceIp
        
        # actions to be done are defined
        msg.actions.append(of.ofp_action_nw_addr.set_dst(serverIp))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.serverDetails[serverIp][0]))
        msg.actions.append(of.ofp_action_output(port = self.serverDetails[serverIp][1]))
     
        # sending message
        self.connection.send(msg)
        
    # Handles the IP packet  
    def handleRequest(self, event, packet):
        num = random.randint(1,100)
        num = num % len(self.serverIp)
        serverIp = self.serverIp[num] 
        log.info("Randomly chosen IP = %s " %serverIp)
        self.installFlowFromServer(event, packet, serverIp)
        self.installFlowFromClient(event, packet, serverIp)

    # sends the packet to the specified port
    def resend_packet (self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in

        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)

        self.connection.send(msg)


    # Normal switch modules ( l2 switch )
    def act_like_switch (self, packet, packet_in):
        
        # mac port table is maintained
        if packet.src not in self.mac_to_port:
            self.mac_to_port[packet.src] = packet_in.in_port

        # installs the flow in switch id dest mac is in table
        # else floods the packet
        if packet.dst in self.mac_to_port:
            # constructing the open flow message
            log.info("Installing flow for dest MAC = %s" %packet.dst)
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet)
            action = of.ofp_action_output(port = self.mac_to_port[packet.dst])
            msg.idle_timeout = IDLE_TIMEOUT
            msg.hard_timeout = HARD_TIMEOUT
            msg.data = packet_in
            msg.buffer_id = packet_in.buffer_id
            msg.actions.append(action)
            self.connection.send(msg)

        else:
            self.resend_packet(packet_in, of.OFPP_ALL)

    # handles the incoming packet        
    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port
        # if packet type is ARP
        if packet.type == packet.ARP_TYPE:
            arpPacket = packet.next
            # if it is ARP reply
            if arpPacket.opcode == arp.REPLY:
                log.info("Received arp reply from ip = %s" %arpPacket.protosrc)
                # if it has fake MAC 
                if arpPacket.hwdst == self.lb_mac:
                    log.info("Upating server details for %s" % arpPacket.protosrc)
                    self.updateServerDetails(event.port, arpPacket.hwsrc, IPAddr(arpPacket.protosrc))
                else:
                    # else act like a normal switch
                    self.act_like_switch(packet, event.ofp)
            elif arpPacket.opcode == arp.REQUEST:
                log.info("Received arp request from ip = %s" % arpPacket.protosrc)
                # if ARP request is for service IP
                if arpPacket.protodst == self.serviceIp:
                    log.info("Sending proxy ARP reply")
                    self.sendProxyArpReply(event, arpPacket)
                else:
                    # else act like a normal switch
                    self.act_like_switch(packet, event.ofp)
        elif packet.type == packet.IP_TYPE:
            ipPacket = packet.next
            # if destination of ip is service ip
            if ipPacket.dstip == self.serviceIp:
                log.info("Receiving request to service IP")
                self.handleRequest(event, packet)
            else:
                self.act_like_switch(packet, event.ofp)
                          
        else:
            # unknow packet type
            log.info("Unknown Packet type: %s" % packet.type)
            return
        return

# launch
def launch(ip, servers): 
    log.info("Loading Load Balancer module")
    server_ips = servers.replace(","," ").split()
    server_ips = [IPAddr(x) for x in server_ips]
    service_ip = IPAddr(ip)
    core.registerNew(IpLoadBalancer, service_ip, server_ips)
