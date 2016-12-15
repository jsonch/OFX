"""
Module that implements two avant-guard functions: 
push based rules
TCP Syn validation
"""
import socket
import struct
import threading
import time
import cPickle as pickle
from ctypes import *

MODULEID = 0x40

# dependencies for this module
dependencies = ['uthash.h']

# message type definitions for this module. 
ENABLECONNECTIONVALIDATION=0x01 # enable TCP handshake validation. 
ADDTRIGGER=0x02 # add a trigger to the switch.
TRIGGERRESPONSE=0x03 # trigger alert from switch to controller.

# match for a trigger. 
class Trigger(object):
    src=None
    dst=None
    matchType=None
    threshold=None

class ControllerComponent(object):
    MODULEID = 0x40
    def __init__(self, ofxControllerInterface):
        self.ofxSys = ofxControllerInterface
        # the handler for messages from the switch by this module.
        self.mainHandler = self.handleModuleMessage

    def enableConnectionValidation(self, sendToSwitch):
        """
        Enable TCP connection validation on a switch.
        """    
        data = ''
        msg = self.ofxSys.buildModuleMessage(self.MODULEID, ENABLECONNECTIONVALIDATION, data)
        sendToSwitch(msg)

    def addTrigger(self, sendToSwitch, srcip, dstip, matchType, threshold):
        """
        Add a trigger to the switch. (for either packets or bytes counts.)
        """
        t = Trigger()
        t.src = srcip
        t.dst = dstip
        t.matchType = matchType
        t.threshold = threshold
        data = pickle.dumps(t)
        msg = self.ofxSys.buildModuleMessage(self.MODULEID, ADDTRIGGER, data)
        sendToSwitch(msg)

    def handleModuleMessage(self, data, datapathSendFcn):
        print("avantguard module: controller message handler not implemented.")
        messageType, content = self.ofxSys.unpackModuleMessage(data)
        if messageType == TRIGGERRESPONSE:
            print("a trigger fired on the switch.")

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
        # the agent running on the switch that interfaces with the switch and controller.
        self.ofxAgent = ofxAgent
        # methods provided by the switch agent to send to the controller and switch.
        self.sendToSwitchFcn = ofxAgent.injectToSwitch
        self.sendToControllerFcn = ofxAgent.injectToController

        # start the thread that polls for triggers.
        self.activeTriggers = {} # the active triggers.
        self.triggerDelay = 1 # how long to wait before a re-poll.
        t = threading.Thread(target=self.pollForTriggers, args=())
        t.start()


    def handleModuleMessage(self, data):
        """
        Handles messages from the controller directed to this module.
        """
        (messageType, content) = self.ofxAgent.unpackModuleMessage(data)
        # print "\tmessage type: %s"%messageType
        if messageType == ENABLECONNECTIONVALIDATION:
            self.enableConnectionValidation(content)
        elif messageType == ADDTRIGGER:
            self.addTrigger(content)
        else:
            print ("avantguard module: unknown message type %s"%messageType)

    def enableConnectionValidation(self, content):
        """
        To enable TCP connection validation, add a low priority 
        rule to redirect TCP traffic to the datapath agent. 
        Then, the datapath agent will add higher priority rules 
        to route traffic once the TCP connection is established.
        """
        # redirect all the traffic to the processing component, 
        # which can install rules for each flow. 
        print ("adding low priority rule to redirect tcp packets to datapath agent.")
        matchPatternIn = "priority=1, dl_type=0x0800, ip_proto=6"
        self.ofxAgent.redirectToDpAgent(matchPatternIn, self.MODULEID)
        print ("adding default output rule to flood packets.")
        # bug in pica8 if you try to match udp packets here, it doesn't work.
        matchPatternOut = "priority=1, dl_type=0x0800"
        actionOut = "FLOOD"
        self.ofxAgent.redirectFromDpAgent(matchPatternOut, actionOut, self.MODULEID)

    def addTrigger(self, content):
        """
        Add a high priority flood rule for the given match pattern. 
        Start a thread to poll it. If the threshold goes above the 
        given threshold, send an alert message to the controller. 
        """
        t = pickle.loads(content)
        self.ofxAgent.addIpCounterFlow(t.src, t.dst, self.MODULEID)
        self.activeTriggers[(t.src, t.dst)] = t

    def pollForTriggers(self):
        """
        Starts a loop to poll for all the active triggers. 
        """
        while True:
            if len(self.activeTriggers)>0:
                # build the list of active flows.
                activeFlows= {}
                flowStats = self.ofxAgent.getFlowStats(self.MODULEID)
                lines = flowStats.split('\n')
                flowrecs = lines[1:-1]
                for flowrec in flowrecs:
                    fields = flowrec.split(",")
                    src = None
                    dst = None
                    pct = None
                    bct = None
                    for field in fields:
                        kv = field.split("=")
                        if len(kv)<2:
                            pass
                        else:
                            key=kv[0]
                            value = kv[1]
                            if 'nw_src' in key:
                                src = value.split(' ')[0]
                            elif 'nw_dst' in key:
                                dst = value.split(' ')[0]
                            elif 'n_packets' in key:
                                pct = value.split(' ')[0]
                            elif 'n_bytes' in key:
                                bct = value.split(' ')[0]
                    if src != None and dst != None:
                        key = (src, dst)
                        activeFlows[key] = {'pct':pct, 'bct':bct}
                # check the stats of all the active triggers.
                # if the threshold for any of them is met, alert 
                # the controller.
                for key, t in activeTriggers.items():
                    if key in activeFlows:
                        stats = activeFlows[key]
                        if stats[t.matchType]>t.threshold:
                            self.activateTrigger(trigger, stats[t.matchType])
            # wait before polling again.
            time.sleep(self.triggerDelay)

    def activateTrigger(self, trigger, statValue):
        """
        send an alert to the controller that a trigger is met.                            
        """
        trigger.statValue = statValue
        data = pickle.dumps(trigger)
        msg = self.ofxAgent.buildModuleMessage(self.MODULEID, TRIGGERRESPONSE, data)
        self.ofxAgent.injectToController(msg)