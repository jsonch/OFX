#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import subprocess
import sys
import time
import signal

# Running ofx: 
# 1) start controller.
# 2) start this script, which will spawn the network, OFX, and the connections.
# 3) do whatever. A nice test is:
#    h1 cd ../measurement_scripts
#    h1 sudo ./click autogen_send_pkts.click

def compileOFX():
    cmd = "gcc -w genericDpAgent.c -o genericDpAgent -ldl -lpthread -g -rdynamic"
    subprocess.Popen(cmd, shell=True)    
    cmd = "gcc -w -c -fPIC nullmodule.c -o nullmodule.o"
    subprocess.Popen(cmd, shell=True)
    cmd = "gcc -shared -o ofxmodule.so nullmodule.o"
    subprocess.Popen(cmd, shell=True)

class OfxInstance(object):
    """
    Manages an OFX agent for a single switch. 
    """
    def __init__(self, switchName, tapInterface, listenPort, internalPort):
        self.switchName = switchName
        self.tapInterface = tapInterface
        self.listenPort = listenPort
        self.internalPort = internalPort
        self.datapathPort = 666
        # self.internalPort = internalPort # Internal port = port between management agent and datapath agent. Need to implement this.
    def spawnTap(self):
        """
        spawn the tap interface, add it to the switch.
            $VSCTL add-port $bridgename $ofinterface -- set Interface $ofinterface ofport_request=$ofport -- set interface $ofinterface type=internal
        """
        cmd = 'sudo ovs-vsctl add-port %s %s -- set Interface %s ofport_request=%s -- set interface %s type=internal'%(self.switchName, self.tapInterface, self.tapInterface, self.datapathPort, self.tapInterface)
        subprocess.call(cmd, shell=True)
        cmd = "sudo ifconfig %s mtu 1600"%self.tapInterface
        subprocess.call(cmd, shell=True)
        cmd = "sudo ifconfig %s up"%self.tapInterface
        subprocess.call(cmd, shell=True)
        cmd = "sudo ifconfig %s promisc"%self.tapInterface
        subprocess.call(cmd, shell=True)

    def startAgent(self, controllerip, controllerport):
        """
        Start the OFX agent for the switch.
        echo "calling: sudo python switchAgent.py $1 $controllerip $controllerport $listenip $listenport $bridgename $ethinterface $ofport &"
        sudo python switchAgent.py $1 $controllerip $controllerport $listenip $listenport $bridgename $ethinterface $ofport &        
        """
        cmd = 'sudo ovs-vsctl set-controller %s tcp:127.0.0.1:%s'%(self.switchName, self.listenPort)
        subprocess.Popen(cmd, shell=True)

        cmd = ['sudo', 'python', 'switchAgent.py'] + ["mininet", controllerip, str(controllerport), '127.0.0.1', str(self.listenPort), self.switchName, self.tapInterface, str(self.datapathPort), str(self.internalPort)]
        # cmd = "sudo python switchAgent.py %s %s %s %s %s %s %s %s &"%\
        # ("mininet", controllerip, controllerport, '127.0.0.1', self.listenPort, self.switchName, self.tapInterface, self.datapathPort)
        print cmd        
        self.agentProcess = subprocess.Popen(cmd)
        print ("agent started for %s"%self.switchName)
    def shutDown(self):
        """
        Shut down this OFX instance.
        """
        print ("shutting down OFX agent for %s"%self.switchName)
        self.agentProcess.terminate()
        return

def simpleNet():                                                                                                                             
    """
    A custom mininet topology for testing ofx.

               h1   -----|
                             |
               h2 --  switch -- OFX process
                             |          |
                             |          |
                             |          |
                        controller  -----
    """
    # spawn some switches. 
    switchIds = [1, 2]
    switchObjs = []
    switchNames = ['s%s'%sid for sid in switchIds]

    net = Mininet( autoStaticArp=True )

    s1 = net.addSwitch(switchNames[0]) 
    switchObjs.append(s1)
    s2 = net.addSwitch(switchNames[1])
    switchObjs.append(s2)
    h1 = net.addHost( 'h1', ip='1.1.1.1', mac='00:00:00:00:00:01')
    h2 = net.addHost( 'h2', ip='1.1.1.5', mac='00:00:00:00:00:02') 
    
    net.addLink( h1, s1 )                                                                                                                   
    net.addLink(s1, s2)
    net.addLink( s2, h2 )

    net.start()

    print ("compiling OFX..")
    compileOFX()
    print ("attempting to start OFX..")

    tapInterfaces = ['tap%s'%sid for sid in switchIds]
    listenPorts = [10000+sid for sid in switchIds]
    internalPorts = [22000 + sid for sid in switchIds]

    ofxObjs = []
    for i in range(len(switchObjs)):
        print ("spawning agent for switch %s"%i)
        testOFXInstance = OfxInstance(switchNames[i], tapInterfaces[i], listenPorts[i], internalPorts[i])
        testOFXInstance.spawnTap()
        testOFXInstance.startAgent('127.0.0.1', 6633)
        ofxObjs.append(testOFXInstance)
        time.sleep(.1)

    print ("waiting 10 seconds for OFX to start..")
    time.sleep(10)
    print ("done waiting for OFX.")
    CLI( net )

    # shutdown the OFX instances.
    for ofxObj in ofxObjs:
        ofxObj.shutDown()

    net.stop()

if __name__ == '__main__':
    simpleNet()