# sets up the OFX agents for mininet.
import subprocess
import sys
import time
import signal

# This config also needs to be in startTopo.py
switchIds = [1]
switchNames = ['s%s'%sid for sid in switchIds]
tapInterfaces = ['tap%s'%sid for sid in switchIds]
listenPorts = [10000+sid for sid in switchIds]
internalPorts = [22000 + sid for sid in switchIds]
controllerip ='127.0.0.1'
controllerport= 6633

def main():
    # compile OFX (for all switches)
    print ("compiling OFX switch agent...")
    compileOFX()
    print ("done.")
    print ("configuring interconnects between all OFX agents and switches.")
    # Configure all the switches to interconnect with their OFX agent.
    for i in range(len(switchIds)):
        ofxCfg = OfxInstance(switchIds[i], switchNames[i], tapInterfaces[i], listenPorts[i], internalPorts[i])
        ofxCfg.setupFastPath()
        ofxCfg.setupControllerPath()
        ofxCfg.getStartCommand()
        time.sleep(.1)
    print "to stop all agents, use stopAgents.sh"

# compile OFX.
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
    def __init__(self, agentId, switchName, tapInterface, listenPort, internalPort):
        self.agentId = agentId
        self.switchName = switchName
        self.tapInterface = tapInterface
        self.listenPort = listenPort
        self.internalPort = internalPort
        self.datapathPort = 666
        # self.internalPort = internalPort # Internal port = port between management agent and datapath agent. Need to implement this.
    def setupFastPath(self):
        """
        set up the tap interface between the OFX agent and the switch -- this is for faster packet transfers.
        Note: may produce errors if tap already exists.
        """
        print ("setting up fast path interface between OFX agent %s and switch %s"%(self.agentId, self.switchName))
        cmd = 'sudo ovs-vsctl add-port %s %s -- set Interface %s ofport_request=%s -- set interface %s type=internal'%(self.switchName, self.tapInterface, self.tapInterface, self.datapathPort, self.tapInterface)
        subprocess.call(cmd, shell=True)
        cmd = "sudo ifconfig %s mtu 1600"%self.tapInterface
        subprocess.call(cmd, shell=True)
        cmd = "sudo ifconfig %s up"%self.tapInterface
        subprocess.call(cmd, shell=True)
        cmd = "sudo ifconfig %s promisc"%self.tapInterface
        subprocess.call(cmd, shell=True)
        print ("done")
    def setupControllerPath(self):
        """
        Configures the switch so that its OFX agent acts as a proxy between the switch and the controller.
        """
        print ("setting controller of %s to point at OFX agent %s"%(self.switchName, self.agentId))
        cmd = 'sudo ovs-vsctl set-controller %s tcp:127.0.0.1:%s'%(self.switchName, self.listenPort)
        subprocess.Popen(cmd, shell=True)
        print ("setting OVS version for switch.")
        cmd = "sudo ovs-vsctl set bridge %s protocols=OpenFlow13,OpenFlow10,OpenFlow11"%self.switchName
        subprocess.Popen(cmd, shell=True)
        print ("done.")
    def getStartCommand(self):
        """
        Print the command that actually starts the OFX agent. 
        """
        cmd = ['sudo', 'python', 'switchAgent.py'] + ["mininet", controllerip, str(controllerport), '127.0.0.1', str(self.listenPort), self.switchName, self.tapInterface, str(self.datapathPort), str(self.internalPort)]
        cmdStr = " ".join(cmd)
        print ("to start OFX agent %s for switch %s, run:"%(self.agentId, self.switchName))
        print cmdStr        

if __name__ == '__main__':
    main()
