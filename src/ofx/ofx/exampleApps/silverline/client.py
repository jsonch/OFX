"""
simple udp client that sends a message to a server.
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
import time


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
    main(serverip, userid, dataid)