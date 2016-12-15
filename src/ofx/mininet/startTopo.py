#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import subprocess
import sys
import time
import signal

# starts a simple mininet topology: a switch connecting two hosts and a controller.

# This config also needs to be in startOfxAgent.py
switchIds = [1]
switchNames = ['s%s'%sid for sid in switchIds]
tapInterfaces = ['tap%s'%sid for sid in switchIds]
listenPorts = [10000+sid for sid in switchIds]
internalPorts = [22000 + sid for sid in switchIds]
controllerip ='127.0.0.1'
controllerport= 6633


def simpleNet():                                                                                                                             
    net = Mininet( autoStaticArp=True )

    s1 = net.addSwitch(switchNames[0]) 
    h1 = net.addHost( 'h1', ip='1.1.1.1', mac='00:00:00:00:00:01')
    h2 = net.addHost( 'h2', ip='1.1.1.5', mac='00:00:00:00:00:02') 
    
    net.addLink( h1, s1 )                                                                                                                   
    net.addLink( h2, s1 )
    net.start()
    CLI( net )
    net.stop()

if __name__ == '__main__':
    simpleNet()