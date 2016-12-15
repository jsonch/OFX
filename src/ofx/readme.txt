working but incomplete OFX implementation that runs on mininet.

vm credentials: user/ofx

Requirements (all pre-installed on the VM):
1) mininet
2) pip
3) ryu
4) twink
5) dpkt
sudo apt-get install mininet python-pip
sudo pip install ryu twink dpkt
sudo ./patchtwink.sh #local patch to fix a bug in twink.

Directories:
mininet: code for spawning mininet.
controller: code for controller applications. 
ofx: code for OFX:
	- controller Library (ofx/controllerLib/*)
	- example controller apps that use OFX (ofx/exampleApps/* -- botminer is the only one I've re-tested in mininet)
	- OFX modules from the paper (ofx/ofxModules/* -- each module has a python file with controller and switch level code, and a c file that processes packets at the switch level)
	- the OFX switch-level agent (ofx/switchAgent/genericDpAgent.c is the low level agent that processes packets, switchAgent/switchAgent.py is the higher level agent that connects to the controller).

Instructions: 
1) Open 3 terminal windows. One for mininet, one for OFX, one for controller.

2) start mininet topology <in window 1>
cd mininet
sudo python startTopo.py

3) start the OFX switch agent. <in window 2>
cd ofx/switchAgent
sudo python setupOfxAgents.py
# follow instructions to start agent.
# to stop agents, use: sudo ~/Desktop/OFX/src/ofx/ofx/switchAgent/stopAgents.sh

4) start an example controller app. <in window 3>
# botminer is the only one I've tested recently.
cd ofx/exampleApps/botminer
sudo ryu-manager ofxbotminer.py
# the example apps are messy with temp files, copy a bunch of temp files to their current directory. The only important file here is ofxbotminer.py
# the agent occasionally crashes here when the controller start.

5) in the mininet window, run a script to generate traffic.
h1 cd hostScripts
h1 sudo python sendRandomFlows.py h1-eth0 1.1.1.1

6) If you are running botminer, you should see: 
- the mininet host sending packets
- the OFX agent collecting flow records and sending them to the controller
- the controller getting flow records from the OFX agent and passing them to the placeholder for botminer