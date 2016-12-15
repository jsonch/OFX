"""
Simple udp server, using raw sockets.
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


serverport = 666

# ip and port where the declassifier is listening, on mininet.
declassifierIp = '11.1.1.2'
declassifierPort = 55555

# ip and port where the declassifier is listening, on pica8 testbed.
# declassifierIp = '127.0.0.1'
# declassifierPort = 55555


def main(serverInterface, serverIp):
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
    print ("Starting listening loop.")
    currentPermissions = set() # cache of the current permissions for flows.

    while True:
        pkt, srcaddr = s.recvfrom(1514) # 1500 is the mtu.. but still will this work?
        print srcaddr
        # print srcaddr
        # srcaddr = list(srcaddr)
        # srcaddr[2] = 4
        # srcaddr = tuple(srcaddr)
        if len(pkt)>4:
            ethIn = Ethernet(pkt)
            if type(ethIn.data) == IP:
                ipIn = ethIn.data
                if type(ipIn.data) == UDP:
                    udpIn = ipIn.data
                    if (ipIn.dst == serveripn) and (ipIn.data.dport == serverport):
                        # print ("got server packet")
                        userid, dataid = struct.unpack("ii", udpIn.data)  
                        # print ("got request for user id: %s data id: %s"%(userid, dataid)) 
                        # print ("writing flow information to file. ")
                        # flowData = "%s,%s,%s,%s:%s\n"%(socket.inet_ntoa(ipIn.src), socket.inet_ntoa(ipIn.dst), udpIn.sport, udpIn.dport, userid)
                        # f = open(flowDataFile, "a")
                        # f.write(flowData)
                        # f.close()

                        # pack the information about the flow, that
                        # you send to the declassifier.
                        permission = userid
                        flowPermission = ''
                        flowPermission += ipIn.dst
                        flowPermission += ipIn.src
                        flowPermission += struct.pack("!H", udpIn.dport)
                        flowPermission += struct.pack("!H", udpIn.sport)
                        flowPermission += struct.pack("!i", permission)
                        # add the permissions, if they're not added yet.
                        if flowPermission not in currentPermissions:
                            currentPermissions.add(flowPermission)
                            # print ("intended message: %s (%s) --> %s (%s)"%\
                            #     (socket.inet_ntoa(ipIn.dst), udpIn.dport, socket.inet_ntoa(ipIn.src), udpIn.sport))
                            # send the permission information to the declassifier.
                            # print ("sending %s bytes to declassifier"%len(flowPermission))
                            declassifierSocket.send(flowPermission)
                            # time.sleep(.000001)
                        # print("flow permissions sent to declassifier.")
                        # response just indicates whether the user has
                        # permission to access it according to the 
                        # server. If you see a 0 response at the client, 
                        # something is wrong.
                        if userid == dataid:
                            message = struct.pack("i", 1)
                        else:
                            message = struct.pack("i", 0)
                        # print ("sending message back to client")
                        udpOut = UDP()
                        udpOut.sport = udpIn.dport
                        udpOut.dport = udpIn.sport
                        udpOut.data = message
                        udpOut.ulen=len(udpOut)
                        udpOut = UDP(str(udpOut))

                        ipOut = IP(src=ipIn.dst, dst=ipIn.src)
                        ipOut.p = 0x11
                        ipOut.data = UDP(str(udpOut))
                        ipOut.v = 4
                        ipOut.len = len(ipOut)

                        # put the data id into the dcsp field. (first 6 bits of tos)
                        ipOut.tos = dataid << 2

                        ethOut = Ethernet(src = ethIn.dst, dst=ethIn.src,type=ethernet.ETH_TYPE_IP, data = ipOut)
                        # print ("-----")
                        # print len(message)
                        # print len(str(udpOut))
                        # print len(str(ipOut))
                        # print len(ethOut)
                        # print len(udpIn)
                        # print len(udpOut)
                        # print "_--------_"
                        # print str(udpIn).encode('hex_codec')
                        # print str(udpOut).encode('hex_codec')
                        # print `ethOut`
                        ethOut = str(ethOut)
                        s.sendto(ethOut, srcaddr)


            # mysteryaddr = tuple(mysteryaddr)     
            # s.sendto(pktstr, mysteryaddr)
        
if __name__ == '__main__':
    serverInterface, serverIp = sys.argv[1::]
    main(serverInterface, serverIp)  