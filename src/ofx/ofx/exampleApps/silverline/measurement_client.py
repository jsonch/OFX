"""
sends packets out to the silverline server, 
measures how quickly you get packets back.

"""
import socket
import struct
import sys
import time
import subprocess

# parameters: duration of test, server address, client interface.
duration = 10
serverip = '1.1.1.5'
clientinterface = 'h1-eth0'


def main():
    pingCmd = 'hping3 %s --udp --file valid.bin -d 8 -p 666 -i u1000'%(serverip)
    monitorCmd = ['./netpps.sh', clientinterface]
    send_p = subprocess.Popen(pingCmd, shell=True, stdout = subprocess.PIPE)
    monitor_p = subprocess.Popen(monitorCmd, stdout=subprocess.PIPE)
    ct = 0
    while ct<duration:
        line = monitor_p.stdout.readline()
        if line != '':
            print line.rstrip()
            ct += 1
    monitor_p.kill()
    send_p.kill()
    stopCmd = 'killall hping3'
    subprocess.Popen(stopCmd, shell=True)


if __name__ == '__main__':
    main()