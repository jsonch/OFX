"""
An example Ryu application that uses extended switch functionality. 
This version reads from a switch variable for experiments that require 
the controller to start in different modes.
"""

import os, sys
import dpkt
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ofxLib import *
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    moduleDir = '/home/ubuntu/ryuLib/secModule'

    # moduleFile = '/home/ubuntu/ryuLib/secModule.py'

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.openFlowRules = []  # the match objects from the openflow rules.
        self.experimentMode = int(os.environ['EXPERIMENTMODE']) # Which mode do we run as?
        # need to do an avant guard init no matter what.
        self.OFXSecurityInit()
        # mode 0: no extended functionality. Just a learning controller.
        if self.experimentMode == 0:
            pass            
        # mode 1: Learning controller with rule conditionals. Install a conditional 
        # for each rule. 
        elif self.experimentMode == 1:
            pass            

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # reset miss_send_len. This shouldn't be needed. Seems like a bug in ryu? or ovs?
        req = parser.OFPSetConfig(datapath, ofproto.OFPC_FRAG_NORMAL, ofproto.OFPCML_NO_BUFFER)
        datapath.send_msg(req)

        print ("switch connected via openflow..")
        # load the module into the OFX agent on the switch.
        switchAuxIp = datapath.address[0]
        switchAuxPort = int(os.environ['SWITCHAUXPORT'])
        self.ofxLib.connectToSwitch(datapath, switchAuxIp, switchAuxPort)
        print ("switch connected via auxiliary port.")

        # make a call to route all traffic through the data path agent.
        match = parser.OFPMatch()
        self.enableTCPConnectionValidation(datapath, match)




    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def multiModePacketIn(self, ev):
        """
        handles packet ins differently based on what mode the controller is 
        running in.
        """
        # mode 0: learning controller with no extended functionality.
        if self.experimentMode == 0:
            self.standard_packet_in_handler(ev)
        # mode 1: learning controller with rule conditionals.
        elif self.experimentMode == 1:
            self.ruleConditionalPacketIn(ev)

    def standard_packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def ruleConditionalPacketIn(self, ev):
        """
        Add a conditional trigger to each rule installed.
        """
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        data = msg.data
        pkt = packet.Packet(data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", src, dst, in_port, len(data))
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        # print self.mac_to_port[dpid]
        # print "src: %s dst: %s data length: %s"%(src, dst, len(data))
        # even here, the data length is short.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            # print ("set out_port")
        else:
            out_port = ofproto.OFPP_FLOOD

        # send the packet out with openflow.
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # install a flow with openflow.
            self.add_flow(datapath, 10, match, actions)
            # # add a sample polling conditional to the rule.
            interval = 1         
            print ("adding polling conditional with interval: %s"%interval)
            basetriggervalue = 100
            adjustedtriggervalue = float(basetriggervalue*interval)
            self.addSamplePollingConditionalRule(datapath, match, value = adjustedtriggervalue, interval = interval)


    # code to use the security module.
    def OFXSecurityInit(self):
        """
        Initialize the OFX security module.
        """
        self.ofxLib = OfxLib(self.moduleDir)
        # import the module we want to use.
        imp.load_source("ofxModule", "%s"%(self.moduleDir + "/" + self.ofxLib.primaryFile))
        global ofxModule
        import ofxModule as ofxModule
        self.ofxLib.registerEventHandler("TriggerReportMsg", self.handleConditionReport)

    def handleConditionReport(self, sourceDataplane, ofxMessage):
        """
        Print a conditional status update from the switch.
        """
        print "trigger status report from switch. trigger TYPE: %s"%ofxMessage.trigger.triggerAction
        print "\trigger condition: %s %s %s"%(ofxMessage.trigger.valueType, \
            ofxMessage.trigger.triggerOperator, ofxMessage.trigger.triggerValue)
        print "\tcurrent value: %s"%(ofxMessage.value)

    def addSamplePollingConditionalRule(self, datapath, match, value = 100, interval = 1.0):
        """
        adds a conditional to the rule specified by match, using OFX
        """
        # install a conditional trigger for the newly added rule. 
        matchStr = bytearray()
        match.serialize(matchStr, 0)
        matchStr = str(matchStr)
        # build the conditional.
        triggerAction = "statusUpdate"
        checkType = "bps"
        condition = ">="
        trigger = ofxModule.Trigger(\
             matchStr, triggerAction, checkType, condition, value)
        OFXMsg = ofxModule.InstallTriggerMsg(\
            matchStr, trigger, interval)
        self.ofxLib.sendMessage(datapath, OFXMsg)

    def enableTCPConnectionValidation(self, datapath, match):
        """
        enables TCP connection validation on a switch using a datapath
        agent handler.
        """
        print ("enabling TCP connection validation.")
        matchStr = bytearray()
        match.serialize(matchStr, 0)
        matchStr = str(matchStr)
        OFXMsg = ofxModule.EnableConnectionValidationMsg(matchStr)
        self.ofxLib.sendMessage(datapath, OFXMsg)

