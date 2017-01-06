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
# To run the proxy, assuming your controller is at localhost:6633, 
# and you want the proxy to listen at localhost:9999, 
# start this script and your controller 
# sudo python startTopo.py
# ryu-manager exampleController.py
# then, in another window, run:
# sudo python ofProxy.py localhost 6633 localhost 9999
proxyport = 9999
def simpleNet():                                                                                                                             
    net = Mininet( autoStaticArp=True )

    s1 = net.addSwitch("s1") 
    h1 = net.addHost( 'h1', ip='1.1.1.1', mac='00:00:00:00:00:01')
    h2 = net.addHost( 'h2', ip='1.1.1.5', mac='00:00:00:00:00:02') 

    cmd = 'sudo ovs-vsctl set-controller s1 tcp:127.0.0.1:%s'%(proxyport)
    subprocess.Popen(cmd, shell=True)    

    cmd = "sudo ovs-vsctl set bridge s1 protocols=OpenFlow13"
    subprocess.Popen(cmd, shell=True)
    
    net.addLink( h1, s1 )                                                                                                                   
    net.addLink( h2, s1 )
    net.start()
    CLI( net )
    net.stop()

if __name__ == '__main__':
    simpleNet()