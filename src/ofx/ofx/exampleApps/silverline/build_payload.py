"""
builds a payload for the silverline server that 
requests data with the specified tag, as the specified user.

Input: 
user id (i.e. logged in user)
data id (i.e. requested data tag)
filename (i.e. where to dump the payload)
"""
import socket
import struct
import sys
import time


def main(userid, dataid, binfilename):
    userid = int(userid)
    dataid = int(dataid)
    print ("building payload with user id: %s data id: %s"%(userid, dataid))
    message = ''
    message += struct.pack("i", userid)
    message += struct.pack("i", dataid)
    f = open(binfilename, 'w')
    f.write(message)
    f.close()

if __name__ == '__main__':
    userid, dataid, binfilename = sys.argv[1::]
    main(userid, dataid, binfilename)