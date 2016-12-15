"""
Botminer data collecting module. 
"""
import socket
import struct
import threading
import time
import cPickle as pickle

# Module ID, for OFX internal reference.
MODULEID = 0x40


# dependencies for this module
dependencies = ['uthash.h']

# message type definitions for this module. 
# controller <--> switch
STARTMONITORING = 0x01 # add a trigger. 
ALERT=0x02 # send an alert to the controller about a trigger.

# switch <--> data plane
GETFLOWS = 0x11
FLOWSTATS = 0x22


class ControllerComponent(object):
    """
    The component that gets loaded by the controller.
    This provides an interface for control programs to use this module.
    """
    MODULEID = 0x40


    flowDictAsic = {}
    flowDictDp = {}

    def __init__(self, ofxControllerInterface):
        self.ofxSys = ofxControllerInterface
        # the handler for messages from the switch by this module.
        self.mainHandler = self.handleModuleMessage

    def startMonitoring(self, sendToSwitch, updatePeriod, threshold):
        """
        Start monitoring for DDoS conditions.
        """
        print ("starting DDoS monitoring.")
        data = struct.pack("!ii", updatePeriod, threshold)
        msg = self.ofxSys.buildModuleMessage(self.MODULEID, STARTMONITORING, data)
        sendToSwitch(msg)

    def handleModuleMessage(self, data, datapathSendFcn):
        messageType, content = self.ofxSys.unpackModuleMessage(data)
        if messageType == ALERT:
            self.handleSwitchAlert(content, datapathSendFcn)

    def handleSwitchAlert(self, content, datapathSendFcn):
        """
        Handles an alert from a switch.
        """
        rate = pickle.loads(str(content))
        print ("got an alert from the switch (rate = %s bytes)"%rate)


class SwitchComponent(object):
    """
    The component that gets loaded by the OFX agent on the switch.
    """
    MODULEID = 0x40
    # messages that this module wants to handle on the switch.
    def __init__(self, ofxAgent):
        # the OpenFlow messages this module wants to intercept.
        self.OFInterceptors = {}
        # self.OFInterceptors = {'ofp_packet_in':self.handlePacketInMessage}
        # the handler for messages directed to this module.
        self.mainHandler = self.handleModuleMessage
        self.dpHandler = self.handleDpMessage
        # the agent running on the switch that interfaces with the switch and controller.
        self.ofxAgent = ofxAgent
        # methods provided by the switch agent to send to the controller and switch.
        self.sendToSwitchFcn = ofxAgent.injectToSwitch
        self.sendToControllerFcn = ofxAgent.injectToController
        # socket to the data path component for this module.
        self.dpSocket = None
        self.flowStatsAsic = {} # flow stats according to the OpenFlow tables.
        self.flowStatsOFX = {} # flow stats according to the OFX data plane agent.
        self.lastCheckTime = 0
        self.currentTime = 0
        self.lastByteCts = {}

    def checkForDDoS(self, threshold):
        """
        Checks the flow tables for a DDoS attack.
        """
        self.currentTime = time.time()
        interval = float(self.currentTime-self.lastCheckTime)      
        # only do the check once per second.
        if (interval)<1:
            return
        keys = set(self.flowStatsAsic.keys() + self.flowStatsOFX.keys())
        totalChange = 0
        # see how much the byte count of each flow has changed since 
        # this function was last called.
        for key in keys:
            currentByteCt = self.flowStatsAsic.get(key, 0) + self.flowStatsOFX.get(key, 0)
            lastByteCt = self.lastByteCts.get(key, 0)
            self.lastByteCts[key] = currentByteCt
            change = currentByteCt - lastByteCt
            totalChange += change
        byterate = totalChange / interval
        rate = byterate * 8
        self.lastCheckTime = self.currentTime
        if rate > threshold:
            print ("THRESHOLD REACHED.")
            print ("\tobserved rate: %s"%rate)
            print ("\tthreshold: %s"%threshold)
            data = pickle.dumps(rate)
            msg = self.ofxAgent.buildModuleMessage(self.MODULEID, ALERT, data)
            self.ofxAgent.injectToController(msg)        

    def handleDpMessage(self, msgType, data):
        """
        Handles messages from the OFX data path component.
        struct FlowEntryNoHash{
            struct FlowKey key;
            uint32_t permission;
            uint32_t added; // Has the rule been added?
            uint32_t byteCt; // how many bytes have we seen?
        };
        """
        if msgType == FLOWSTATS:
            flowCt = len(data)/24
            idx = 0
            ptr = 0
            while idx<flowCt:
                ptr = idx * (24)
                src = socket.inet_ntoa(data[ptr:ptr+4])
                dst = socket.inet_ntoa(data[ptr+4:ptr+8])
                sport,dport = struct.unpack("!HH", data[ptr+8:ptr+12])
                permission,added,byteCt = struct.unpack("!III",data[ptr+12:ptr+24])
                # print ("DP AGENT flow %s: %s (%s) --> %s (%s) -- %s bytes"%(idx, src, sport, dst, dport, byteCt))
                key = (src,dst,sport,dport)
                if key not in self.flowStatsOFX:
                    self.flowStatsOFX[key] = 0
                self.flowStatsOFX[key] =byteCt
                idx += 1
        else:
            print ("DDoS module: unknown message type.")

    def handleModuleMessage(self, data):
        """
        Handles messages directed to this module.
        """
        # print ("got a message in silverline module.")
        (messageType, content) = self.ofxAgent.unpackModuleMessage(data)
        # print "\tmessage type: %s"%messageType
        if messageType == STARTMONITORING:
            self.startMonitoring(content)

    def startMonitoring(self, content):
        """
        Start monitoring for DDoS attacks. 
        """
        time.sleep(1)
        (interval, threshold) = struct.unpack("!ii", content)
        t = threading.Thread(target=self.localMonitoringThread, args=(interval,threshold))
        t.start()
        # install a tap for traffic, using OFX.
        print ("tapping UDP traffic to monitor for DDoS attacks.")
        # matchPatternIn = "priority=1, dl_type=0x0800, ip_proto=17"
        matchPatternIn = "priority=1"
        self.ofxAgent.tapToDpAgent(matchPatternIn, self.MODULEID)

    def localMonitoringThread(self, interval, threshold):
        """
        Collects data from the OpenFlow component of the switch about what 
        flows are installed. 
        """
        print ("starting DDoS monitoring thread with update interval: %s"%interval)
        while True:
            # get the stats from the ASIC.
            flowStats = self.ofxAgent.getFlowStatsDict(self.MODULEID)
            # get the stats from the datapath agent.
            self.ofxAgent.sendToDp(MODULEID, GETFLOWS, '')

            self.flowStatsAsic = {k:v['bct'] for k, v in flowStats.items()}
            # now do the check?
            self.checkForDDoS(threshold)
            # wait until the next interval.   
            time.sleep(interval)