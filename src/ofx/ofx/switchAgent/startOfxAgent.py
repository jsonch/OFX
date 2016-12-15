# starts the ofx switch level agent for a mininet switch.
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


def main():
    # compile OFX (for all switches)
    compileOFX()
    # Start OFX Process for each switch that proxies between the switch and the controller, and has an 
    # additional fast-path connection to the switch.
    ofxObjs = []
    for i in range(len(switchIds)):
        print ("spawning agent for switch %s"%i)
        ofxProc = OfxInstance(switchNames[i], tapInterfaces[i], listenPorts[i], internalPorts[i])
        ofxProc.spawnTap()
        ofxProc.startAgent('127.0.0.1', 6633)
        ofxObjs.append(ofxProc)
        time.sleep(.1)
    print ("OFX should be running, press ctrl-c to quit.")
    print ("waiting 10 seconds for OFX to start..")
    time.sleep(10)

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

if __name__ == '__main__':
    main()
