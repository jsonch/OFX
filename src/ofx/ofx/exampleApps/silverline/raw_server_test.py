"""
Test silverline server that floods tagged packets out.
1) loads X permissions into the classifier.
2) sends Y valid packets (i.e. with correct permissions.)
3) sends Z invalid packets. (i.e. with invalid permissions.)
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

# how quickly can we install permissions onto OFX.
permissionRate = 200
permissionDelay = 1.0/permissionRate

rate = 100
delay = 1.0/rate

serverport = 666

# ip and port where the declassifier is listening, on mininet.
# declassifierIp = '11.1.1.2'
# declassifierPort = 55555

# ip and port where the declassifier is listening, on pica8 testbed.
declassifierIp = '127.0.0.1'
declassifierPort = 55555

clientMac= '000000000001'
serverMac= '000000000002'
# parameters:
permissionct = 5000 # number of flow permissions to generate.
validflowct = 1000 # number of valid flows to generate.
invalidflowct = 1000 # number of invalid flows to generate.
# validflowct + invalidflowct <permissionct
pktsPerFlow = 1 # number of packets per flow.
invalidPacketLoc = 0 # where in the flow is the invalid packet?

def main(serverInterface, serverIp):
    dstaddr = (serverInterface, 2048, 0, 1, clientMac.decode('hex')) # where to send the packets.

    # open a socket to the switch here. Just do a send when you have a 
    # permission that you want to add. You can work in the controller 
    # interface later on, connect right to the switch, for now.
    declassifierSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    declassifierSocket.connect((declassifierIp, declassifierPort))
    print ("connected to declassifier.")
    serveripn = socket.inet_aton(serverIp)
    # bind on an extra socket, so the kernel knows the udp port is opened.
    s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s1.bind((serverIp, serverport))
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(3)) # 3 = ETH_P_ALL, all protocol.
    # s.bind((serverip, serverport))
    s.bind((serverInterface, 0))

    print ("generating permissions")
    permissionrecords = set()
    for i in range(permissionct):
        dstip = socket.inet_aton(socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))))
        srcip = socket.inet_aton(serverIp)
        dstport = random.randint(1, 50000)
        srcport = serverport

        permissionrecord = (dstip, srcip, dstport, srcport)
        permissionrecords.add(permissionrecord)
        permission = 1 # the valid permission is always 1.
        flowPermission = ''
        flowPermission += srcip
        flowPermission += dstip
        flowPermission += struct.pack("!H", srcport)
        flowPermission += struct.pack("!H", dstport)
        flowPermission += struct.pack("!i", permission)
        declassifierSocket.send(flowPermission)
        time.sleep(permissionDelay)
    declassifierSocket.close()
    print ("%s unique flow permissions generated and send to declassifier."%len(permissionrecords))
    print ("generating valid flows.")
    validflows = []
    permissionrecords = list(permissionrecords)
    for i in range(validflowct):
        validrecord = permissionrecords[i]
        dstip, srcip, dstport, srcport = validrecord  
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
            ipOut.tos = 1 << 2 # these are valid flows, so put 1 into the ip dscp field.
            ethOut = Ethernet(src=serverMac.decode('hex'), dst=clientMac.decode('hex'), type=ethernet.ETH_TYPE_IP, data = ipOut)
            eo = str(ethOut)
            flow.append(str(ethOut))
        validflows.append(flow)
    print ("%s valid flows generated, with %s packets each."%(len(validflows), len(validflows[0])))
    
    print ("generating invalidflows")    
    invalidflows = []
    for i in range(len(validflows), len(validflows)+invalidflowct):
        validrecord = permissionrecords[i]
        dstip, srcip, dstport, srcport = validrecord   
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
            if j == invalidPacketLoc:
                ipOut.tos = 0 << 2 # mark the invalid packet.
            else:
                ipOut.tos = 1 << 2 # mark the valid packets.

            ethOut = Ethernet(src=serverMac.decode('hex'), dst=clientMac.decode('hex'), type=ethernet.ETH_TYPE_IP, data = ipOut)
            flow.append(str(ethOut))
        invalidflows.append(flow)

    print ("%s invalid flows generated, with %s packets each."%(len(invalidflows), len(invalidflows[0])))

    print ("sending valid flows packets to: %s"%str(dstaddr))
    for flow in validflows:
        for pktstr in flow:
            s.sendto(pktstr, dstaddr)
            time.sleep(delay)

    print ("sending invalid flow packets to: %s"%str(dstaddr))
    for flow in invalidflows:
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