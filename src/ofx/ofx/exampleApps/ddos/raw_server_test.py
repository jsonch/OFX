"""
Test botminer 
2) sends N packets with random src ip / port.
"""
import sys
import struct
import socket,IN
import fcntl
import socket
from dpkt import ethernet
from dpkt import ip
from dpkt import udp
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.udp import UDP
import time
import random


rate = 1000
delay = 1.0/rate

serverport = 666


clientMac= '000000000001'
serverMac= '000000000002'
# parameters:
flowct = 10000 # number of flows to generate.
pktsPerFlow = 10 # number of packets per flow.


def getFlowKey(serverIp):
    dstip = socket.inet_aton(socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))))
    srcip = socket.inet_aton(serverIp)
    dstport = random.randint(1, 50000)
    srcport = serverport
    return dstip, srcip, dstport, srcport


def main(serverInterface, serverIp):
    dstaddr = (serverInterface, 2048, 0, 1, clientMac.decode('hex')) # where to send the packets.
    serveripn = socket.inet_aton(serverIp)
    # bind on an extra socket, so the kernel knows the udp port is opened.
    s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s1.bind((serverIp, serverport))
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(3)) # 3 = ETH_P_ALL, all protocol.
    # s.bind((serverip, serverport))
    s.bind((serverInterface, 0))

    print ("generating flows.")
    flows = []
    for i in range(flowct):
        dstip, srcip, dstport, srcport = getFlowKey(serverIp)  
        flow = []     
        for j in range(pktsPerFlow):
            message = struct.pack("i", 1)
            udpOut = UDP()
            udpOut.sport = srcport
            udpOut.dport = dstport
            udpOut.data = message
            udpOut.ulen=len(udpOut)
            udpOut = UDP(str(udpOut))
            ipOut = IP(src=srcip, dst=dstip)
            ipOut.p = 0x11
            ipOut.data = UDP(str(udpOut))
            ipOut.v = 4
            ipOut.len = len(ipOut)
            ethOut = Ethernet(src=serverMac.decode('hex'), dst=clientMac.decode('hex'), type=ethernet.ETH_TYPE_IP, data = ipOut)
            eo = str(ethOut)
            flow.append(str(ethOut))
        flows.append(flow)
    print ("%s flows generated, with %s packets each."%(len(flows), len(flows[0])))
    

    print ("sending flows packets to: %s"%str(dstaddr))
    for flow in flows:
        for pktstr in flow:
            s.sendto(pktstr, dstaddr)
            time.sleep(delay)

    print ("everything send. exiting.")
    return


            # mysteryaddr = tuple(mysteryaddr)     
            # s.sendto(pktstr, mysteryaddr)
        
if __name__ == '__main__':
    serverInterface, serverIp = sys.argv[1::]
    main(serverInterface, serverIp)  