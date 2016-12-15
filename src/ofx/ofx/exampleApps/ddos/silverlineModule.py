"""
Silverline declassification module.
"""
import socket

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
    MODULEID = 0x20
    def __init__(self, ofxControllerInterface):
        self.ofxSys = ofxControllerInterface
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
        data = flowPermissionBin
        msg = self.ofxSys.buildModuleMessage(self.MODULEID, ADDFLOWPERMISSION, data)
        sendToSwitch(msg)

class SwitchComponent(object):
    """
    The component that gets loaded by the OFX agent on the switch.
    """
    MODULEID = 0x20
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
        # socket to the data path component for this module.
        self.dpSocket = None

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
        matchPatternOut = "priority=1, dl_type=0x0800"
        actionOut = "FLOOD"
        self.ofxAgent.redirectFromDpAgent(matchPatternOut, actionOut, self.MODULEID)
        # open socket to data path component. 
        print ("opening socket to data path component.")
        self.dpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.dpSocket.connect(('127.0.0.1', dataPathPort))
        print ("connected to data path component.")


    def addFlowPermission(self, msgContent):
        """
        add permissions for the flow.
        (forward the message to the socket to the data path component.)
        """
        # print ("got request to add flow permission. (content len: %s)"%len(msgContent))
        self.dpSocket.send(msgContent)
        # that's it?


