"""
A driver that runs on the switch. 
"""
from __future__ import print_function
import time, sys, struct, threading, socket, os, signal
import cPickle as pickle
import imp
import importlib
import subprocess
import struct
import random

import twink.ofp4.build as ofbuild
import twink.ofp4.parse as ofparse
import twink.ofp4.oxm as oxm

# ryu imports to add flows faster.
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser

import Queue


ofctlbin = None
# ofctlbin = "/ovs/bin/ovs-ofctl" # for pica8.
# ofctlbin = 'sudo ovs-ofctl' # for mininet.
# OFX constants.
OFX_MESSAGE=0x1
OFX_MANAGEMENT_MODULE=0xffffffff

# OFX management message types.
# start load files message, send files, end message.
OFX_LOAD_MODULE_START=0x1 # payload: string containing module name.
OFX_LOAD_MODULE_FILE=0x2 # payload: pickled tuple: (filename, contents)
OFX_LOAD_MODULE_END=0x3 # payload: compilation instructions.
OFX_LOAD_MODULE_FILE_PIECE=0x4 # payload: pickled tuple: (filename, total len, contents)

# OFX management agent <--> datapath agent format:
# | Message length | Module ID | Message Type | Content 
# all values (besides content) are integers in network format.
# OFX System module IDs
OFX_MANAGEMENT_AGENT = 0x1

# OFX management agent <--> datapath agent message types.
OFX_ADD_UDP_FLOW = 0x1 # datapath -> management: add an OpenFlow Rule.
# Add udp flow counter message content: 12 bytes
# | Src IP | Dst IP | Src Port | Dst Port | ( 4 | 4 | 2 | 2) 

OFX_ADD_UDP_DSCP_FLOW = 0x2 # datapath -> management: add an OpenFlow Rule.
# | Src IP | Dst IP | Src Port | Dst Port | DSCP ( 4 | 4 | 2 | 2 | 4) 

OFX_PACKET_UP = 0x3 # datapath -> management: send packet to controller.
# | PACKET BYTES (length varies)

OFX_ADD_TCP_FLOW = 0x4 # datapath -> management: add an OpenFlow Rule.
# Add tcp flow counter message content: 12 bytes
# | Src IP | Dst IP | Src Port | Dst Port | ( 4 | 4 | 2 | 2) 


class SwitchAgent(object):

    flowModQueue = Queue.LifoQueue()
    flowModRate = 10
    flowModDelay = 1.0/flowModRate
    # some definitions we don't use.
    buffer_size = 4096
    delay = 0.00001
    # the name of the file that the data path agent loads. 
    # (must agree with definition in dp agent)
    dpAgentSharedObject = "ofxmodule.so"
    tempDir = "./tempFiles/"
    sys.path.insert(0, tempDir)
    actionTable=66
    loadedModules = {}

    # ordered lists of functions to call 
    # for each type of OpenFlow message.

    OFInterceptors = {\
    'ofp_packet_in':[],\
    'ofp_packet_out':[],\
    'ofp_flow_mod':[],\
    'ofp_multipart_reply':[]\
    }
    
    moduleHandlers = {}
    dpModuleHandlers = {}
    class FakeDp(object):
        class FakeProto(object):
            OFP_HEADER_SIZE= 8
            OFP_VERSION=0x04
            OFP_HEADER_PACK_STR='!BBHI'
        ofproto=FakeProto()
    fakedp=FakeDp()

    def dprint(self, message):
        """ Prints output to a log file. """  
        msg = "%s: %s"%(time.time(),message)
        print(msg, file=self.logf)
        self.logf.flush()


    def init(self, platform, controllerOFIp, controllerOFPort, \
        switchListenIp, switchListenPort,\
        activeBridgeName, datapathLink, datapathLinkId, internalPort):
        """
        Startup that should be called after constructor.
        """
        # 3: spawn the proxy to the OpenFlow controller and switch.
        self.OFProxy = BaseProxy(controllerOFIp, controllerOFPort, \
            switchListenIp, switchListenPort,\
            controlInterceptMethod = self.interceptFromControlOF,\
            switchInterceptMethod = self.interceptFromSwitchOF, \
            switchAgent=self)
        #    This does not return until the connections are established.
        self.OFProxy.startProxy()

        # This adds a low priority rule to skip OFX. Need 
        # to correctly set up the pipeline.
        self.setupOFXTables()
        # now this thread can stick around and see if everything 
        # is still running.
        # proxy threads..
        # data path agent...
    def __init__(self, platform, controllerOFIp, controllerOFPort, \
        switchListenIp, switchListenPort,\
        activeBridgeName, datapathLink, datapathLinkId, internalPort):
        global ofctlbin
        # Open the debug file.
        self.logf = sys.stdout
        # self.logf = open("%s-switchagent.log"%activeBridgeName,"w", buffering=1)


        if "mininet" in platform:
            ofctlbin = 'sudo ovs-ofctl' # for mininet.
        elif "pica8" in platform:
            ofctlbin = "/ovs/bin/ovs-ofctl" # for pica8.


        self.activeBridgeName = activeBridgeName
        self.datapathLink = datapathLink
        self.datapathLinkId = datapathLinkId
        self.internalPort = internalPort
        # 1) Open a socket for the datapath agent to connect to.
        self.dpSock = self.startDpSocket(self.internalPort)
        # 2) Start the datapath agent.        
        cmd = ['./genericDpAgent', datapathLink, activeBridgeName, internalPort]
        self.dpAgentProc = subprocess.Popen(cmd)
        # wait for the datapath agent to start up, before you 
        # continue. This should be done with signaling, or parsing 
        # for a line in output.
        time.sleep(5)
        return


    def setupOFXTables(self):
        """
        Set up the OFX tables.
        Should be per module, done when you load modules.
        For now, just resubmit to table 1.
        """
        self.dprint ("setting up OFX tables. ")
        # use twink to generate a low priority "goto" rule here.
        (header, cookie, cookie_mask, table_id, command, idle_timeout,\
            hard_timeout, priority, buffer_id, out_port, out_group,\
            flags) = \
        (None, 0, 0, 0, ofbuild.OFPFC_ADD, 0, 0, 0, \
            ofbuild.OFP_NO_BUFFER, ofbuild.OFPP_ANY, ofbuild.OFPP_ANY,\
            0)
        match = ofbuild.ofp_match(None, None, None)        
        instructions = [ofbuild.ofp_instruction_goto_table(None, None, 1)]

        ofMessage = ofbuild.ofp_flow_mod(header, cookie, cookie_mask, \
            table_id, command, idle_timeout, hard_timeout, priority, \
            buffer_id, out_port, out_group, flags, match, instructions)
        ofMessage = str(ofMessage)
        self.injectToSwitch(ofMessage)   

    # example add flow method.
    def testAddFlow(self):
        self.dprint ("testing add flow.")
        time.sleep(5)
        ct = 0
        src='1.1.1.4'
        dst='1.1.1.5'
        for sport in range(1,50000):
            for dport in range(1, 50000):
                self.addUDPCounterFlow(src, dst, sport, dport)
                if ct % 100 == 0:
                    self.dprint ("number of flows added: %s"%ct)
                ct += 1
                time.sleep(.0001)


    def handleOFMessage(self, data):
        """
        Handles OpenFlow messages.
        """    

        # experimenter message -> ofx.
        version = ord(data[0])
        messageType = ord(data[1])
        mlen = len(data)
        # self.dprint ("version: %s type: %s len: %s"%(version, messageType, mlen))
        exp_id = None
        if messageType == 4:
            exp_id, exp_type = struct.unpack("!II", data[8:16])

        if exp_id == OFX_MESSAGE:
            contents = data[16::]
            self.handleOFXMessage(exp_id, exp_type, contents)
        else:
            ofMessage = ofparse.parse(data)
            ofMessageType = ofMessage.__class__.__name__
            # else, run it through all the registered interceptors.
            if ofMessageType in self.OFInterceptors:
                for fcn in self.OFInterceptors[ofMessageType]:
                    data = fcn(data)            
            return data

    def handleOFXMessage(self, exp_id, exp_type, contents):
        """
        Handles OFX messages (experimenter messages with appropriate 
        type code).
        """
        # self.dprint ("exp_id: %s exp_type: %s"%(exp_id, exp_type))
        ofxModuleId = exp_type
        # if it goes to the OFX management module, send it there.
        if ofxModuleId==OFX_MANAGEMENT_MODULE:
            self.handleOFXManagementMessage(contents)

        # else, send it to whatever module's function is registered to 
        # handle the id.
        elif ofxModuleId in self.moduleHandlers:
            self.moduleHandlers[ofxModuleId](contents)
        else:
            self.dprint ("unknown  module id: %s"%ofxModuleId)

    # def handleOFMessageSlow(self, data):
    #     """
    #     Handles OpenFlow messages.
    #     """    
    #     ofMessage = ofparse.parse(data)
    #     ofMessageType = ofMessage.__class__.__name__
    #     # if its an OFX message, handle it here.
    #     if ofMessageType == 'ofp_experimenter_' and ofMessage.experimenter == OFX_MESSAGE:
    #         self.handleOFXMessage(data)
    #         return data
    #     else:
    #         # else, run it through all the registered interceptors.
    #         # if ofMessageType in self.OFInterceptors:
    #         #     for fcn in self.OFInterceptors[ofMessageType]:
    #         #         data = fcn(data)            
    #         return data
    # def handleOFXMessageSlow(self, data):
    #     """
    #     Handles OFX messages (experimenter messages with appropriate 
    #     type code).
    #     """
    #     ofMessage = ofparse.parse(data)
    #     ofxModuleId = ofMessage.exp_type
    #     # if it goes to the OFX management module, send it there.
    #     if ofxModuleId==OFX_MANAGEMENT_MODULE:
    #         self.handleOFXManagementMessage(ofMessage.data)

    #     # else, send it to whatever module's function is registered to handle the id.
    #     elif ofxModuleId in self.moduleHandlers:
    #         self.moduleHandlers[ofxModuleId](ofMessage.data)


    def handleOFXManagementMessage(self, data):
        """
        Handles OFX system messages from the controller. 
        """
        messageType, contents = self.unpackModuleMessage(data)
        self.dprint ("got an OFX management message. TYPE: %s"%messageType)
        # handle the management message as needed.
        if messageType == OFX_LOAD_MODULE_START:
            self.loadModuleStart(contents)
        elif messageType == OFX_LOAD_MODULE_FILE:
            self.loadModuleFile(contents)
        elif messageType == OFX_LOAD_MODULE_END:
            self.loadModuleEnd(contents)
        elif messageType == OFX_LOAD_MODULE_FILE_PIECE:
            self.loadModuleFilePiece(contents)

    def loadModuleStart(self, data):
        """
        Start a module transfer.
        """
        self.newModuleName = data
        self.moduleTransferActive = True
        self.currentBin = ''
        self.dprint ("starting transfer of module: %s"%self.newModuleName)

    def loadModuleFile(self, data):
        """
        Load a file from a module.
        """
        (fileName, bin) = pickle.loads(data)
        filePath = self.tempDir + fileName
        self.dprint ("got file %s (%s)"%(filePath, len(bin)))
        with open(filePath, "w") as f:
            f.write(bin)

    def loadModuleFilePiece(self, data):
        """
        loads a part of a file from a module.
        """
        (fileName, totalLen, binPart) = pickle.loads(data)
        filePath = self.tempDir + fileName        
        self.currentBin += binPart
        if len(self.currentBin)>= totalLen:
            self.dprint ("got all pieces of file %s (%s)"%(fileName, totalLen))
            with open(filePath, "w") as f:
                f.write(self.currentBin)
            self.currentBin = ''
        else:
            self.dprint ("got part of file %s (%s)"%(fileName, len(self.currentBin)))

    def loadModuleEnd(self, data):
        """
        End a module loading. Do the import and all registration.
        """
        # import the module.
        moduleObj = importlib.import_module(self.newModuleName)
        # load the switch component, pass it a self reference.
        newComponent = moduleObj.SwitchComponent(self)
        self.loadedModules[self.newModuleName] = newComponent
        # register the openflow message interceptors.
        for mtype, fcn in newComponent.OFInterceptors.items():
            self.OFInterceptors[mtype].append(fcn)
        # register the handler for messages to this module id.   
        self.dprint ("registering handler for module ID %s"%newComponent.MODULEID)     
        self.moduleHandlers[newComponent.MODULEID] = newComponent.mainHandler
        self.dpModuleHandlers[newComponent.MODULEID] = newComponent.dpHandler

        self.dprint ("finished transferring module %s"%(self.newModuleName))
        # do any compilation required. (special instructions 
        # could be in this message.)
        self.dprint ("compiling datapath agent module:")
        self.dprint ("----------------------------------")
        self.compileDPModule(self.newModuleName+".c")
        self.dprint ("----------------------------------")
        self.moduleTransferActive = False

    def compileDPModule(self, fileName):
        """
        Loads the packet processing component of an OFX module.
        Has to be called ofxmodule.so, for now.
        """
        # go to the temp directory
        filePath = self.tempDir + fileName
        cmd = 'cd %s'%self.tempDir
        subprocess.call(cmd, shell=True)        
        # compile the extension module.        
        cmd = 'gcc -w -c -fPIC -o %s.o %s -lpthread'%(filePath, filePath)
        self.dprint ("running command: %s"%cmd)
        subprocess.call(cmd, shell=True)
        cmd = 'gcc -shared -o %s %s.o -lpthread'%("ofxmodule.so",filePath)
        self.dprint ("running command: %s"%cmd)
        subprocess.call(cmd, shell=True)
        self.dprint ("datapath module compiled.")
        self.dprint ("signaling data path agent to load module.")
        # signal the datapath agent to load the module...
        self.dpAgentProc.send_signal(14)
        self.dprint ("signal sent..")
        time.sleep(1)

    #### functions a module can call. ####
    def buildModuleMessage(self, moduleId, messageType, content):
        """
        Build a message for a running module. 
        """
        contentLen = len(content)
        msg = struct.pack('!i', messageType)
        msg += struct.pack('!i', contentLen)
        msg += content
        data = self.buildOFXMessage(moduleId, msg)
        return data        

    def buildOFXMessage(self, moduleId, content):
        """
        Builds an OFX message to send to a OFX agent.
        Content is the binary content to send with the message.
        """
        data = ofbuild.ofp_experimenter_header(None,OFX_MESSAGE, moduleId, content)
        return data

    ### new redirect methods. 
    ### Input adds an MPLS tag for the module id. ###
    ### Output, removes the tag for the module ID, sends to a table 
    ### specifically for the module.
    ### maybe the redirectToDpAgent can just redirect to a table for t
    ### the module as well? 
    ### But then what about multiple modules?
    ### Maybe don't give modules any control over flow tables, 
    ### besides redirecting into the packet processor.
    def redirectToDpAgent(self, matchPattern, moduleId):
        """
        adds a rule to redirect packets to a module id.
        """
        rerouteCmd = ofctlbin+ ' -O OpenFlow13 add-flow %s "%s,actions=output:%s"'%\
        (self.activeBridgeName, matchPattern, self.datapathLinkId)
        self.dprint ("switch agent adding rule:")
        self.dprint ("\t%s"%rerouteCmd)
        subprocess.call(rerouteCmd, shell=True)        

    def tapToDpAgent(self, matchPattern, moduleId):
        """
        adds a rule to tap packets to the dp agent. 
        Need to do this with an OpenFlow message instead of ovs, 
        so that we can use the "goto" command instead of resubmit.
        (then you'd only need 1 rule, not 1 for each port)
        """
        rerouteCmd = ofctlbin+ ' -O OpenFlow13 add-flow %s "%s,in_port=1,actions=resubmit(1,1),output:%s"'%\
        (self.activeBridgeName, matchPattern, self.datapathLinkId)
        self.dprint ("switch agent adding rule:")
        self.dprint ("\t%s"%rerouteCmd)
        subprocess.call(rerouteCmd, shell=True)        

        rerouteCmd = ofctlbin+ ' -O OpenFlow13 add-flow %s "%s,in_port=2,actions=resubmit(2,1),output:%s"'%\
        (self.activeBridgeName, matchPattern, self.datapathLinkId)
        self.dprint ("switch agent adding rule:")
        self.dprint ("\t%s"%rerouteCmd)
        subprocess.call(rerouteCmd, shell=True)        

        rerouteCmd = ofctlbin+ ' -O OpenFlow13 add-flow %s "%s,in_port=3,actions=resubmit(3,1),output:%s"'%\
        (self.activeBridgeName, matchPattern, self.datapathLinkId)
        self.dprint ("switch agent adding rule:")
        self.dprint ("\t%s"%rerouteCmd)
        subprocess.call(rerouteCmd, shell=True)        


    def redirectFromDpAgent(self, matchPattern, action, moduleId):
        """
        specifies what happens after a packet comes out of a module. 
        Match pattern is packet header fields, doesn't include mpls 
        tag with the packet id.
        1) add a rule to strip the MPLS tag and resubmit to the action table.
        2) add the rule to the action table with the requested match and action 
        patterns.
        """
        return
        # rerouteCmd = ofctlbin + ' -O OpenFlow13 add-flow %s "priority=2, in_port=%s,actions=resubmit:%s"'%\
        # (self.activeBridgeName, self.datapathLinkId, self.datapathLinkId)
        # self.dprint ("switch agent adding rule:")
        # self.dprint ("\t%s"%rerouteCmd)
        # subprocess.call(rerouteCmd, shell=True)
        # take whatever action the module wants on this kind of packet. 
        action="resubmit(666,1)"
        rerouteCmd = ofctlbin+ ' -O OpenFlow13 add-flow %s "%s, table=%s, in_port=%s, actions=%s"'%\
        (self.activeBridgeName, matchPattern, 0, self.datapathLinkId, action)
        self.dprint ("switch agent adding rule:")
        self.dprint ("\t%s"%rerouteCmd)
        subprocess.call(rerouteCmd, shell=True)

        # what about a low priority rule that says: if a packet comes out of 666 and doesnt match anything, send it back.
        # rerouteCmd = ofctlbin + ' -O OpenFlow13 add-flow %s "in_port=%s, table=%s,priority=2,actions=output:in_port"'%\
        # (self.activeBridgeName,self.datapathLinkId,0)
        # self.dprint ("switch agent adding rule:")
        # self.dprint ("\t%s"%rerouteCmd)
        # subprocess.call(rerouteCmd, shell=True)


        # self.actionTable=2
        # # strip MPLS tag and resubmit to action table, with in_port = module id, as an MPLS packet.
        # match = parser.OFPMatch(in_port=self.datapathLinkId,eth_type=0x8847) # match MPLS packets coming back from the data path agent
        # actions=[parser.OFPActionPopMpls()] # pop mpls tag, set port= module id.
        # instructions = [parser.OFPInstructionGotoTable(self.actionTable)] # redirect to the table that modules can use.
        # inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,\
        #                              actions)] + instructions
        # # build the OpenFlow message obj.
        # mod = parser.OFPFlowMod(datapath=self.fakedp, priority=2,\
        #                             match=match, instructions=inst, table_id=0, cookie=0)
        # mod.serialize()
        # self.injectToSwitch(mod.buf)

        # # add another test rule..
        # match = parser.OFPMatch(eth_type=0x0800)
        # actions=[parser.OFPActionPopMpls(), parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        # mod = parser.OFPFlowMod(datapath=self.fakedp, priority=2,\
        #                             match=match, instructions=inst, table_id=self.actionTable, cookie=0)
        # mod.serialize()
        # self.injectToSwitch(mod.buf)

        # # pica 8's can't strip mpls tags correctly when you use multiple tables.
        # rerouteCmd = ofctlbin + ' -O OpenFlow13 add-flow %s "priority=2, in_port=%s, dl_type=0x8847,mpls_label=%s, actions=pop_mpls:0x0800,resubmit:%s"'%\
        # (self.activeBridgeName, self.datapathLinkId, moduleId, moduleId)
        # self.dprint ("switch agent adding rule:")
        # self.dprint ("\t%s"%rerouteCmd)
        # subprocess.call(rerouteCmd, shell=True)
        # # take whatever action the module wants on this kind of packet. 
        # rerouteCmd = ofctlbin+ ' -O OpenFlow13 add-flow %s "%s, table=%s, in_port=%s, actions=%s"'%\
        # (self.activeBridgeName, matchPattern, 0, moduleId, action)
        # self.dprint ("switch agent adding rule:")
        # self.dprint ("\t%s"%rerouteCmd)
        # subprocess.call(rerouteCmd, shell=True)

        # rerouteCmd = ofctlbin + ' -O OpenFlow13 add-flow %s "priority=2, in_port=%s, dl_type=0x8847,mpls_label=%s, actions=pop_mpls:0x0800,resubmit(%s, %s)"'%\
        # (self.activeBridgeName, self.datapathLinkId, moduleId, moduleId, self.actionTable)
        # self.dprint ("switch agent adding rule:")
        # self.dprint ("\t%s"%rerouteCmd)
        # subprocess.call(rerouteCmd, shell=True)
        # take whatever action the module wants on this kind of packet. 
        # rerouteCmd = ofctlbin+ ' -O OpenFlow13 add-flow %s "%s, table=%s, in_port=%s, actions=%s"'%\
        # (self.activeBridgeName, matchPattern, self.actionTable, moduleId, action)
        # self.dprint ("switch agent adding rule:")
        # self.dprint ("\t%s"%rerouteCmd)
        # subprocess.call(rerouteCmd, shell=True)


        # messing around with adding actions from here for debugging. 
        # try adding an action here that applies an mpls pop and then a resubmit. 
        # actions=[parser.OFPActionPopMpls(), parser.OFPActionSetField(in_port=20)]
        # instructions = [parser.OFPInstructionGotoTable(66)]
        # match = parser.OFPMatch(in_port=666,eth_type=0x8847)
        # self.add_flow_with_instructions(datapath, 10, match, actions, instructions)

        # # add a flow to flood udp packets.
        # match = parser.OFPMatch(in_port=20,eth_type=0x0800, ip_proto=17)
        # actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # self.add_flow_with_instructions(datapath, 10, match, actions, [], 66)

    def getFlowStatsDict(self, moduleId, matchPattern=''):
        """
        Gets the statistics of all the flows added by the module.
        Put them into a dictionary, return the dictionary.
        """
        queryCmd = ofctlbin + " dump-flows %s"%self.activeBridgeName

        ps = subprocess.Popen(queryCmd, shell=True, stdout=subprocess.PIPE)
        flowrecs = ps.communicate()[0]
        lines = flowrecs.split('\n')
        flowrecs = lines[1:-1]
        flowStats = {}
        for flowrec in flowrecs:
            fields = flowrec.split(",")
            src = None
            dst = None
            sport = None
            dport = None
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
                    elif 'tp_src' in key:
                        sport = int(value.split(' ')[0])
                    elif 'tp_dst' in key:
                        dport = int(value.split(' ')[0])
                    elif 'n_packets' in key:
                        pct = value.split(' ')[0]
                    elif 'n_bytes' in key:
                        bct = value.split(' ')[0]
            if src!=None:
                # make a flow record.
                flowKey = (src, dst, sport, dport)
                flowStats[flowKey] = {'bct':int(bct), 'pct':int(pct)}
        return flowStats

    def getFlowStats(self, moduleId, matchPattern=''):
        """
        Gets all the flows added by the module. 
        (cookie=moduleId, for now.)
        """
        queryCmd = ofctlbin + " dump-flows %s"%self.activeBridgeName

        ps = subprocess.Popen(queryCmd, shell=True, stdout=subprocess.PIPE)
        output = ps.communicate()[0]
        return output


    def unpackModuleMessage(self, data):
        """
        Unpacks an OFX message.
        """
        messageType = struct.unpack("!i", data[0:4])[0]
        dataLen = struct.unpack("!i", data[4:8])[0]
        return (messageType, data[8:8+dataLen])


    def interceptFromSwitchOF(self, data):
        """
        intercept openflow messages from the switch to controller. 
        """
        data = self.handleOFMessage(data)
        self.dprint ("message switch -> controller")
        if data != None:
            self.injectToController(data)


    def interceptFromControlOF(self, data):
        """
        intercept openflow messages from the controller to switch.
        """
        data = self.handleOFMessage(data)
        if data != None:
            self.injectToSwitch(data)      
        self.dprint ("message controller -> switch")

    def injectToSwitch(self, data):
        """
        inject a message to the switch, on the OpenFlow channel.
        """
        while self.OFProxy.switchSock == None:
            self.dprint ("trying to send msg, waiting for connection to openflow agent...") 
            time.sleep(1)
        self.OFProxy.switchSock.send(data)

    def injectToController(self, data):
        """
        inject a message to the controller, on the OpenFlow channel.
        """
        while self.OFProxy.controllerSock == None:
            self.dprint ("trying to send msg, waiting for connection to openflow controller...") 
            time.sleep(1)
        self.OFProxy.controllerSock.send(data)

    ####### SOCKET TO DATA PATH AGENT ################################
    def startDpSocket(self, listenPort):
        # start socket.
        dpSockThread = threading.Thread(target = self.socketListenLoop, args = (listenPort,))
        dpSockThread.start()

    def socketListenLoop(self, listenPort):
        """
        listening loop that calls callback whenever a message 
        comes from the socket. 
        Socket must be connected.
        """
        self.dprint ("starting Datapath socket.")
        # open socket and listen for connection.
        dpSock = self.connectDpSocket(int(listenPort))
        self.dpSock = dpSock
        #handle stuff.

        while 1:
            # self.dprint ("GETTING DATA FROM DP SOCK..")
            # get data, send it to handler fcn.
            data = self.recv_n_bytes(dpSock, 4)
            if data == None:
                self.dprint ("connection to DP agent broken.")
                return
            msgLen = struct.unpack("!I", data)[0]
            data=self.recv_n_bytes(dpSock, msgLen-4)
            moduleId = struct.unpack("!I", data[0:4])[0]
            msgType = struct.unpack("!I", data[4:8])[0]
            msgContent = data[8::]
            self.dpSockHandler(msgLen, moduleId, msgType, msgContent)
        return

    def connectDpSocket(self, listenPort):
        """
        connect a socket to the data path agent.
        returns a connected Socket.
        """
        self.dprint ("opening socket for DP agent on %s"%listenPort)
        listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listenSock.bind(('127.0.0.1', listenPort))
        listenSock.listen(5)
        dpSock, dpAddr = listenSock.accept()
        self.dprint ("connection to DP agent made.")
        return dpSock

    def sendToDp(self, moduleId, messageType, messageContent):
        """
        sends a message to the datapath socket. 
        Header format:
        struct ofxDpHeader {
            uint32_t len;
            uint32_t moduleId;
            uint32_t messageType;
        };
        """
        while self.dpSock == None:
            self.dprint ("waiting for socket to data path.")
            time.sleep(1)
        totalLen = len(messageContent) + 12
        msg = struct.pack("!III", totalLen, moduleId, messageType)
        msg += messageContent
        self.dpSock.send(msg)

    def dpSockHandler(self, msgLen, moduleId, msgType, msgContent):
        """
        Handles messages from the data path agent, over the socket.
        """
        if moduleId == OFX_MANAGEMENT_AGENT:
            self.dpSysRequestHandler(msgType, msgContent)
        elif moduleId in self.dpModuleHandlers:
            self.dpModuleHandlers[moduleId](msgType, msgContent)
        else:
            self.dprint ("unknown  module id: %s"%moduleId)
    def dpSysRequestHandler(self, msgType, msgContent):
        """
        Handles system requests from the data agent.
        """
        if msgType == OFX_ADD_UDP_FLOW:
            src = socket.inet_ntoa(msgContent[0:4])
            dst = socket.inet_ntoa(msgContent[4:8])
            sport, dport = struct.unpack("!HH", msgContent[8::])
            self.addUDPCounterFlow(src, dst, sport, dport)
        elif msgType == OFX_ADD_UDP_DSCP_FLOW:
            src = socket.inet_ntoa(msgContent[0:4])
            dst = socket.inet_ntoa(msgContent[4:8])
            sport, dport = struct.unpack("!HH", msgContent[8:12])
            dscp = struct.unpack("!I", msgContent[12::])[0]
            self.addUdpDscpFlow(src, dst, sport, dport, dscp)
        elif msgType == OFX_PACKET_UP:
            self.sendPacketIn(msgContent)
        elif msgType == OFX_ADD_TCP_FLOW:
            src = socket.inet_ntoa(msgContent[0:4])
            dst = socket.inet_ntoa(msgContent[4:8])
            sport, dport = struct.unpack("!HH", msgContent[8::])
            self.addTCPFloodFlow(src, dst, sport, dport)
        else:
            self.dprint("unknown system message type: %s"%msgType)

    ##### Flow installation functions #####
    def addIpCounterFlow(self, src, dst, cookie=0):
        """
        adds a IP flow counter rule to the switch.
        With a cookie, so the module can query for it easily. 
        """
        match = parser.OFPMatch(ipv4_src=src, ipv4_dst=dst, eth_type=0x0800)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]        
        priority = 10
        table_id=0
        mod = parser.OFPFlowMod(datapath=self.fakedp, priority=priority,
                                    match=match, instructions=inst, table_id=table_id, \
                                    cookie=cookie)
        mod.serialize()
        self.injectToSwitch(mod.buf)


    def addUDPCounterFlow(self, src, dst, sport, dport):
        """
        adds a udp flow counter rule to the switch.
        Needs to add a counter for a specific module.
        """
        # self.dprint("adding udp counting flow: %s (%s) -> %s (%s)\n"%(src, dst, sport, dport))

        # match = parser.OFPMatch(ipv4_src=src, ipv4_dst=dst, \
        #     eth_type=0x0800, ip_proto=0x11, udp_src=sport, udp_dst=dport)
        # actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]        
        # priority = 10
        # table_id=0
        # mod = parser.OFPFlowMod(datapath=self.fakedp, priority=priority,
        #                             match=match, instructions=inst, table_id=table_id)
        # mod.serialize()
        # self.injectToSwitch(mod.buf)
        mbuf = writeMod(src, dst, sport, dport, 'udp')
        self.injectToSwitch(mbuf)

    def addTCPFloodFlow(self, src, dst, sport, dport):
        """
        adds a tcp flood rule to the switch.
        Can be used to model a module sending a DO NOT PROCESS message.
        (negative filter)
        """
        # match = parser.OFPMatch(ipv4_src=src, ipv4_dst=dst, \
        #     eth_type=0x0800, ip_proto=0x06, tcp_src=sport, tcp_dst=dport)
        # actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]        
        # priority = 10
        # table_id=0
        # mod = parser.OFPFlowMod(datapath=self.fakedp, priority=priority,
        #                             match=match, instructions=inst, table_id=table_id)
        # mod.serialize()        
        # self.injectToSwitch(mod.buf)
        mbuf = writeMod(src, dst, sport, dport, 'tcp')
        self.injectToSwitch(mbuf)


    def addUdpDscpFlow(self, src, dst, sport, dport, dscp):
        """
        adds a udp flow with a particular dscp tag.
        """
        # self.dprint("adding dscp flow: %s (%s) -> %s (%s)\n"%(src, dst, sport, dport))
        # self.dprint ("adding dscp flow at switch agent (dscp tag = %s)"%dscp)
        # match = parser.OFPMatch(ipv4_src=src, ipv4_dst=dst, \
        #     eth_type=0x0800, ip_proto=0x11, udp_src=sport, udp_dst=dport,\
        #     ip_dscp=dscp)
        # actions = [parser.OFPActionOutput(1),parser.OFPActionOutput(2)]
        # inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]        
        # priority = 10
        # table_id=0
        # mod = parser.OFPFlowMod(datapath=self.fakedp, priority=priority,
        #                             match=match, instructions=inst, table_id=table_id)
        # mod.serialize()
        # self.injectToSwitch(mod.buf)
        mbuf = writeMod(src, dst, sport, dport, 'dscp')
        self.injectToSwitch(mbuf)
        # self.flowModQueue.put(mbuf)
        # self.injectToSwitch(mbuf)



    def sendPacketIn(self, pktBytes):
        """
        Generate and send a packet_in message to the controller, 
        with packet = pktBytes. 
        """
        buffer_id = 0xffffffff # 32 bits
        total_len = len(pktBytes) # 16 bits        
        reason = 1 # 8 bits. action explicitly output to the controller.
        table_id = 0 # 8 bits
        cookie = 0xffffffffffffffff # 64 bits
        matchObj = parser.OFPMatch(in_port=self.datapathLinkId)
        match = bytearray('')
        matchObj.serialize(match, 0)
        padbytes = 0 # 16 bits of padding bytes.
        # then packet bytes.        
        inner = struct.pack("!IHBBQ", buffer_id, total_len, reason, table_id, cookie)\
        + match + chr(0) + chr(0) + pktBytes
        # prepend OF buffer.        
        msgbuf = self.getHeader(10, 8+len(inner)) + inner
        # send the OF packet to the controller.
        self.injectToController(msgbuf)

    def getHeader(self, messageType, messageLen):
        """
        Add an openflow1.3 header to the 
        (openflow 1.3 header)
        """
        header = chr(4) + chr(messageType) + struct.pack("!H",messageLen) \
        + struct.pack("!I",0)
        return header

    def recv_n_bytes(self, socket, n):
        """
        recieve a fixed number of bytes from socket.
        """
        data = ''
        while len(data)< n:
            chunk = socket.recv(n - len(data))
            if chunk == '':
                return None
            data += chunk
        return data


class BaseProxy(object):
    """
    Simple proxy between an OpenFlow switch and a controller. 
    The proxy can take an intercept method for each direction. 
    If one is provided, the proxy passes messages to that method, 
    instead of forwarding them. 
    Also start a keepalive thread for the switch. 
    """
    buffer_size = 4096
    delay = 0.00001

    def __init__(self, controllerIp, controllerPort, \
        switchListenIp, switchListenPort, \
        controlInterceptMethod = None, switchInterceptMethod = None,
        switchAgent = None):
        self.controllerIp = controllerIp
        self.controllerPort = controllerPort
        self.switchListenIp = switchListenIp
        self.switchListenPort = switchListenPort
        self.switchInterceptMethod = switchInterceptMethod
        self.controlInterceptMethod = controlInterceptMethod
        self.dprint = switchAgent.dprint
        # socket to switch and controller.
        self.switchSock = None
        self.controllerSock = None

        self.controllerConnected = False
        self.switchConnected = False
        # OFProxThread = threading.Thread(target = self.startProxy)
        # OFProxThread.start()        
        # return when both connections are complete. 
        # while (not self.controllerConnected) and (not self.switchConnected):
        #     time.sleep(.1)
        # return 1


    def startProxy(self):
        """
        Starts the proxy. 
        """
        # Open the port that listens for a connection from the switch. 
        self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listenSock.bind((self.switchListenIp, self.switchListenPort))
        self.listenSock.listen(5)
        # used to be a while loop here.
        # connect to the controller.
        self.dprint ("connecting to controller at IP: %s port: %s (retrying every second)"%(self.controllerIp, self.controllerPort))            
        while 1:
            try:
                self.controllerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.controllerSock.connect((self.controllerIp, self.controllerPort))
                break
            except socket.error: # retry connection until controller is up.
                time.sleep(1)
        #  listen for a connection from the switch.
        self.controllerConnected = True
        self.dprint ("\tcontroller connected.")
        self.dprint ("waiting for connection from switch. Listening on port: %s"%self.switchListenPort)
        self.switchSock, self.switchAddr = self.listenSock.accept()
        self.dprint ("\tconnection from switch at %s recieved"%str(self.switchAddr))
        self.switchConnected = True
        # start up the forwarding threads.
        self.dprint ("spawning forwarding threads")
        d1 = threading.Thread(target = self.forwardData, args = (self.switchSock, self.controllerSock, self.switchInterceptMethod, "s->c"))
        d2 = threading.Thread(target = self.forwardData, args = (self.controllerSock, self.switchSock, self.controlInterceptMethod, "c->s"))
        d1.start()
        d2.start()
        time.sleep(1)
        # start up the echo loop to keep the switch alive. 
        self.dprint("calling echo loop to keep switch alive.")
        echothread = threading.Thread(target = self.echoLoop, args = ())
        echothread.start()
        return
        # d1.join()
        # d2.join()
        # self.dprint ("forwarding threads finished.")
    def forwardData(self, inSocket, outSocket, interceptMethod = None, direction="?"):
        """
        forwards data from inSocket to outSocket. 
        Passes data through an intercept function first.
        """

        while True:
            # get 4 bytes of the header.
            data = self.recv_n_bytes(inSocket, 4)
            if data == None: # end of socket? Close connection to outSocket and return.
                self.dprint("SOCKET ENDED (%s)"%direction)
                outSocket.close()
                break
            size = struct.unpack("!H", data[2:])[0]-4
            remainingData = self.recv_n_bytes(inSocket, size)
            if remainingData == None:
                self.dprint("SOCKET ENDED (%s)"%direction)
                outSocket.close()
                break
            data = data + remainingData                
            if interceptMethod == None:
                outSocket.send(data)
            else:
                interceptMethod(data)
            time.sleep(self.delay)


    def echoLoop(self):
        echoReqMsg = chr(4) + chr(2) + struct.pack("!H",8) + struct.pack("!I",666)    
        self.dprint ("starting echo loop.")
        while True:
            self.switchSock.send(echoReqMsg)
            time.sleep(2)

    def recv_n_bytes(self, socket, n):
        """
        recieve a fixed number of bytes from socket.
        """
        data = ''
        while len(data)< n:
            chunk = socket.recv(n - len(data))
            if chunk == '':
                return None
            data += chunk
        return data



#### Flow mod messages ####
# some hard coded junk to make writing flow mods easier.
tcpBinStr = ['00', '01', '00', '2b', '80', '00', '0a', '02', '08', '00', '80', '00', '14', '01', '06', '80', '00', '16', '04', '01', '01', '01', '01', '80', '00', '18', '04', '01', '01', '01', '02', '80', '00', '1a', '02', '01', '4d', '80', '00', '1c', '02', '01', 'bc', '00', '00', '00', '00', '00']
tcpBin = bytearray(''.join([x.decode("hex") for x in tcpBinStr]))

udpBinStr = ['00', '01', '00', '2b', '80', '00', '0a', '02', '08', '00', '80', '00', '14', '01', '11', '80', '00', '16', '04', '01', '01', '01', '01', '80', '00', '18', '04', '01', '01', '01', '02', '80', '00', '1e', '02', '01', '4d', '80', '00', '20', '02', '01', 'bc', '00', '00', '00', '00', '00']
udpBin = bytearray(''.join([x.decode("hex") for x in udpBinStr]))

dscpBinStr = ['00', '01', '00', '30', '80', '00', '0a', '02', '08', '00', '80', '00', '10', '01', '01', '80', '00', '14', '01', '11', '80', '00', '16', '04', '01', '01', '01', '01', '80', '00', '18', '04', '01', '01', '01', '02', '80', '00', '1e', '02', '01', '4d', '80', '00', '20', '02', '01', 'bc']
dscpBin = bytearray(''.join([x.decode("hex") for x in dscpBinStr]))

# flood output.
# flowModBinStr = ['04', '0e', '00', '78', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '0a', 'ff', 'ff', 'ff', 'ff', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '01', '00', '2b', '80', '00', '0a', '02', '08', '00', '80', '00', '14', '01', '06', '80', '00', '16', '04', '01', '01', '01', '01', '80', '00', '18', '04', '01', '01', '01', '02', '80', '00', '1a', '02', '01', '4d', '80', '00', '1c', '02', '01', 'bc', '00', '00', '00', '00', '00', '00', '04', '00', '18', '00', '00', '00', '00', '00', '00', '00', '10', 'ff', 'ff', 'ff', 'fb', 'ff', 'e5', '00', '00', '00', '00', '00', '00']

# output to 1 and 2 instead of flooding.
# flowModBinStr = ['04', '0e', '00', '88', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '0a', 'ff', 'ff', 'ff', 'ff', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '01', '00', '2b', '80', '00', '0a', '02', '08', '00', '80', '00', '14', '01', '06', '80', '00', '16', '04', '01', '01', '01', '01', '80', '00', '18', '04', '01', '01', '01', '02', '80', '00', '1a', '02', '01', '4d', '80', '00', '1c', '02', '01', 'bc', '00', '00', '00', '00', '00', '00', '04', '00', '28', '00', '00', '00', '00', '00', '00', '00', '10', '00', '00', '00', '01', 'ff', 'e5', '00', '00', '00', '00', '00', '00', '00', '00', '00', '10', '00', '00', '00', '02', 'ff', 'e5', '00', '00', '00', '00', '00', '00']

# output to JUST 2.
# flowModBinStr = ['04', '0e', '00', '78', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '0a', 'ff', 'ff', 'ff', 'ff', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '01', '00', '2b', '80', '00', '0a', '02', '08', '00', '80', '00', '14', '01', '06', '80', '00', '16', '04', '01', '01', '01', '01', '80', '00', '18', '04', '01', '01', '01', '02', '80', '00', '1a', '02', '01', '4d', '80', '00', '1c', '02', '01', 'bc', '00', '00', '00', '00', '00', '00', '04', '00', '18', '00', '00', '00', '00', '00', '00', '00', '10', '00', '00', '00', '02', 'ff', 'e5', '00', '00', '00', '00', '00', '00']

# goto table 1.
flowModBinStr = ['04', '0e', '00', '68', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '0a', 'ff', 'ff', 'ff', 'ff', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '00', '01', '00', '2b', '80', '00', '0a', '02', '08', '00', '80', '00', '14', '01', '06', '80', '00', '16', '04', '01', '01', '01', '01', '80', '00', '18', '04', '01', '01', '01', '02', '80', '00', '1a', '02', '01', '4d', '80', '00', '1c', '02', '01', 'bc', '00', '00', '00', '00', '00', '00', '01', '00', '08', '01', '00', '00', '00']

flowModBin = bytearray(''.join([x.decode("hex") for x in flowModBinStr]))

matchIdx = 48

def writeTcpMod(src, dst, sport, dport):
    srcOffset = 19
    dstOffset = 27
    sportOffset = 35
    dportOffset = 41
    src = socket.inet_aton(src)
    dst = socket.inet_aton(dst)
    sport = struct.pack("!H", sport)
    dport = struct.pack("!H", dport)
    tcpBin[srcOffset:srcOffset+4] = src
    tcpBin[dstOffset:dstOffset+4] = dst
    tcpBin[sportOffset:sportOffset+2] = sport
    tcpBin[dportOffset:dportOffset+2] = dport
    flowModBin[matchIdx:matchIdx+len(tcpBin)] = tcpBin
    # parseMatch(tcpBin)
    return flowModBin

def writeUdpMod(src, dst, sport, dport):
    srcOffset = 19
    dstOffset = 27
    sportOffset = 35
    dportOffset = 41
    src = socket.inet_aton(src)
    dst = socket.inet_aton(dst)
    sport = struct.pack("!H", sport)
    dport = struct.pack("!H", dport)
    udpBin[srcOffset:srcOffset+4] = src
    udpBin[dstOffset:dstOffset+4] = dst
    udpBin[sportOffset:sportOffset+2] = sport
    udpBin[dportOffset:dportOffset+2] = dport
    flowModBin[matchIdx:matchIdx+len(udpBin)] = udpBin
    return flowModBin

def writeDscpMod(src, dst, sport, dport, dscp):
    dscpOffset = 14
    srcOffset = 24
    dstOffset = 32
    sportOffset = 40
    dportOffset = 46
    src = socket.inet_aton(src)
    dst = socket.inet_aton(dst)
    sport = struct.pack("!H", sport)
    dport = struct.pack("!H", dport)
    dscpBin[srcOffset:srcOffset+4] = src
    dscpBin[dstOffset:dstOffset+4] = dst
    dscpBin[sportOffset:sportOffset+2] = sport
    dscpBin[dportOffset:dportOffset+2] = dport
    dscpBin[dscpOffset] = dscp
    flowModBin[matchIdx:matchIdx+len(dscpBin)] = dscpBin
    return flowModBin

def writeMod(src, dst, sport, dport, mtype):
    mod = None
    if mtype == 'tcp':
        mod =  writeTcpMod(src, dst, sport, dport)
    elif mtype == 'udp':
        mod = writeUdpMod(src, dst, sport, dport)
    elif mtype == 'dscp':
        mod = writeDscpMod(src, dst, sport, dport, 1)
    retmod = bytearray()
    retmod[:] = mod
    return retmod

def genFlowKey():
    dstip = socket.inet_ntoa(struct.pack('!I', random.randint(1, 0xffffffff)))
    srcip = socket.inet_ntoa(struct.pack('!I', random.randint(1, 0xffffffff)))
    dstport = random.randint(1, 50000)
    srcport = random.randint(1, 50000)
    return dstip, srcip, dstport, srcport

# make switchAgent obj global for the exit handler.

def sigterm_handler(signal, frame):
    print ("forwarding SIGTERM to datapath agent.")
    agentPtr.dpAgentProc.send_signal(signal)
    print ("exiting.")
    agentPtr.logf.close()
    sys.exit()

def sigint_handler(signal, frame):
    # forward the kill signal to the datapath agent.
    print ("ignoring SIGINT.")
    return

def main():
    global agentPtr
    platform, controllerIp, controllerPort, switchIp, switchPort, activeBridgeName, datapathLink, datapathLinkId, internalPort = sys.argv[1::]
    controllerPort = int(controllerPort)
    switchPort = int(switchPort)
    datapathLinkId = int(datapathLinkId)
    sa = SwitchAgent(platform, controllerIp, controllerPort, \
        switchIp, switchPort, \
        activeBridgeName, datapathLink, datapathLinkId, internalPort)
    print ("registering exit signal handlers.")
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigterm_handler)
    agentPtr = sa
    sa.init(platform, controllerIp, controllerPort, \
        switchIp, switchPort, \
        activeBridgeName, datapathLink, datapathLinkId, internalPort)
    # register the exit signal handlers.
#
if __name__ == '__main__':
          main()  
