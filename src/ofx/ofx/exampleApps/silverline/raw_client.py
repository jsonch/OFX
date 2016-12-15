"""
simple udp client that sends a message to a server.
uses raw sockets to select random IP addresses and ports.
Input: 
server IP
user id (i.e. logged in user)
data id (i.e. requested data tag)

Function:
Send a packet to the server. 

"""
import socket
import struct
import sys
from dpkt import ethernet
from dpkt import ip
from dpkt import udp
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.udp import UDP
import time


def sendRawRequest(socket, clientaddr, serveraddr, userid, dataid):
    """
    sends 1 raw request from clientaddr to serveraddr.
    """
    message = ''
    message += struct.pack("i", userid)
    message += struct.pack("i", dataid)
    # left off: just added this
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



def rawmain(interface, serverip, userid, dataid):
    """
    raw client main.
    """
    interface = 'h1-eth0' # client interface. Should be parameterized.


    serverport = 666
    userid = int(userid)
    dataid = int(dataid)
    serveraddr = (serverip, serverport)
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(3)) # 3 = ETH_P_ALL, all protocol.
    s.bind((interface, 0))
    print ("socket bound to interface. Starting to send packets.")
    clientaddr = (socket.inet_aton('99.99.99.99'), 22222)
    sendRawRequest(s, clientaddr, serveraddr, userid, dataid)





def main(serverip, userid, dataid):
    userid = int(userid)
    dataid = int(dataid)
    print ("sending request with user id: %s data id: %s"%(userid, dataid))
    serverport = 666
    # opent he socket.
    serveraddr = (serverip, serverport)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    st = time.time()
    for i in range(10):
        intval = sendOneRequest(serveraddr, sock, userid, dataid)
        print ("response %s from server: %s in %s seconds"%(i, intval, time.time()-st))
        time.sleep(.5)
        st = time.time()

def sendOneRequest(serveraddr, sock, userid, dataid):
    """
    Send one request to the server @ serveraddr using sock.
    """
    # build the message
    message = ''
    message += struct.pack("i", userid)
    message += struct.pack("i", dataid)
    # send the message
    sock.sendto(message, serveraddr)
    # wait for the reply...
    retbytes, retaddr = recv_n_bytes(4, sock)
    if retbytes == None:
        print "connection ended from server."
        quit()
    else:
        intval = struct.unpack("i", retbytes)[0]
        # print ("got %s from server"%int(intval))
    return intval


def recv_n_bytes(n, socket):
    """
    recieve a fixed number of bytes from socket.
    """
    data = ''
    while len(data)< n:
        chunk, addr = socket.recvfrom(n - len(data))
        if chunk == '':
            return None, None
        data += chunk
    return data, addr


if __name__ == '__main__':
    serverip, userid, dataid = sys.argv[1::]
    rawmain(serverip, userid, dataid)
    # main(serverip, userid, dataid)