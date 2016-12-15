"""
Silverline declassification module.
"""
import socket
import time

# Module ID, for OFX internal reference.
MODULEID = 0x20


# dependencies for this module
dependencies = ['uthash.h']

# message type definitions for this module. 
ENABLEDECLASSIFIER = 0x01 # enable the declassifier.
ADDFLOWPERMISSION = 0x02 # enable permissions for the flow.

dataPathPort = 44444 # port that the dp agent listens on.


class ControllerComponent(object):
    """
    The component that gets loaded by the controller.
    This provides an interface for control programs to use this module.
    """
    MODULEID = MODULEID
    def __init__(self, ofxControllerInterface):
        self.permissionCt = 0

        self.ofxSys = ofxControllerInterface
        self.mainHandler = self.handleModuleMessage
    def enableDeclassifier(self, sendToSwitch):
        """
        Tells the switch to enable the declassifier.
        For all udp traffic. But this can be for a certain flow 
        in the future.
        """
        data = "no_data"
        msg = self.ofxSys.buildModuleMessage(self.MODULEID, ENABLEDECLASSIFIER, data)
        sendToSwitch(msg)
    def addFlowPermission(self, sendToSwitch, flowPermissionBin):
        """
        Adds a flow permission to a switch.
        """
        self.permissionCt += 1
        if (self.permissionCt % 1000) == 0:
            print ("%s permissions added (in OFX controller component)"%self.permissionCt)

        data = flowPermissionBin
        msg = self.ofxSys.buildModuleMessage(self.MODULEID, ADDFLOWPERMISSION, data)
        sendToSwitch(msg)
    def handleModuleMessage(self, data, datapathSendFcn):
        """
        handle message from the switch.
        """
        print ("handler not implemented in silverline.")

class SwitchComponent(object):
    """
    The component that gets loaded by the OFX agent on the switch.
    """
    MODULEID = MODULEID
    # messages that this module wants to handle on the switch.
    def __init__(self, ofxAgent):
        # the OpenFlow messages this module wants to intercept.
        self.OFInterceptors = {}
        # self.OFInterceptors = {'ofp_packet_in':self.handlePacketInMessage}
        # the handler for messages directed to this module.
        self.mainHandler = self.handleModuleMessage
        # handler for messages from the data path component to the 
        # switch management component.
        self.dpHandler = self.handleDpMessage

        # the agent running on the switch that interfaces with the switch and controller.
        self.ofxAgent = ofxAgent
        # methods provided by the switch agent to send to the controller and switch.
        self.sendToSwitchFcn = ofxAgent.injectToSwitch
        self.sendToControllerFcn = ofxAgent.injectToController
        self.permissionCt = 0
        self.time = time.time()


    def handleDpMessage(self, msgType, data):
        """
        Handles messages from the data path component.
        """
        print ("silverline module got a message from the data path.(len = %s)"%len(data))
        print ("this shouldn't happen?")
        return

    def handleModuleMessage(self, data):
        """
        Handles messages directed to this module.
        """
        # print ("got a message in silverline module.")
        (messageType, content) = self.ofxAgent.unpackModuleMessage(data)
        # print "\tmessage type: %s"%messageType
        if messageType == ENABLEDECLASSIFIER:
            self.enableDeclassifier()
        elif messageType == ADDFLOWPERMISSION:
            self.addFlowPermission(content)

    def enableDeclassifier(self):
        """
        Enables the declassifier.
        1) redirect packets to the data path component.
        2) Open Socket to data path component.
        """
        # redirect to data path component.
        print ("enabling silverline declassifier")
        print ("adding low priority rule to redirect udp packets to declassifier.")
        matchPatternIn = "priority=1, dl_type=0x0800, ip_proto=17"
        self.ofxAgent.redirectToDpAgent(matchPatternIn, self.MODULEID)
        print ("adding default output rule to flood packets.")
        # bug in pica8 if you try to match udp packets here, it doesn't work.
        matchPatternOut = "priority=2, dl_type=0x0800"
        actionOut = "FLOOD"
        self.ofxAgent.redirectFromDpAgent(matchPatternOut, actionOut, self.MODULEID)

    def addFlowPermission(self, msgContent):
        """
        add permissions for the flow.
        (forward the message to the socket to the data path component.)
        """
        self.permissionCt += 1
        if (self.permissionCt % 1000) == 0:
            compTime = time.time() - self.time
            self.time = time.time()
            print ("%s permissions added (in OFX manager) (%s sec)"%(self.permissionCt, compTime))
        self.ofxAgent.sendToDp(self.MODULEID, ADDFLOWPERMISSION, msgContent)


