#
# OFX based declassifier control application. 
# 1) load the OFX declassification module.
# 2) send the command to the switch to start the declassifier.
# 3) that's it?


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib import hub 
import socket
import struct
import time
# grab the latest ofxLib version
import shutil
shutil.copy('../controller/ofxLib.py', "./")
import ofxLib

# module location. 
modulefile = '../modules/ddosdetector/ddosdetectorModule.py'


class SimpleSwitch13(app_manager.RyuApp):


    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # OFX startup: set the interface and give it control 
    # of all experimenter messages from the switch.
    ofxInterface = ofxLib.OfxInterface()
    @set_ev_cls(ofp_event.EventOFPExperimenter, MAIN_DISPATCHER)
    def switchMsgHandler(self, ev):
        datapath_send = ev.msg.datapath.send
        msg = ev.msg
        msg.serialize()
        msg_bytes = msg.buf
        self.ofxInterface.mainHandler(msg_bytes, datapath_send)

    # OFX startup: load the modules that you want onto the switch.
    ofxInterface.loadModule(modulefile)
    # OFX startup: reference to the interface of the module you loaded.
    ddosDetectorInterface = ofxInterface.loadedInterfaces['ddosdetectorModule']


    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_port = {}
        self.packetct = 0
        self.activeDatapaths = []


    def addFloodRules(self, parser, datapath):
        """
        Adds forwarding rules that flood each packet.
        (to the forwarding table that's independent of OFX)
        """
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto_v1_3.OFPP_FLOOD)]
        self.add_flow(datapath, 0, match, actions, buffer_id=None, table_id=1)


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
        self.addFloodRules(parser, datapath)
        
        # install the default rule (tap to OFX and route)     
        # match = parser.OFPMatch()
        # actions = [parser.OFPActionOutput(666)]
        # instructions = [parser.OFPInstructionGotoTable(1)]
        # self.add_flow(datapath, 0, match, actions)

        # OFX: push loaded modules down to this switch. (i.e. silverline, botminer, etc)
        self.ofxInterface.pushModulesToSwitch(datapath.send)

        # OFX: start DDoS monitoring. 
        self.ddosDetectorInterface.startMonitoring(datapath.send, 1, 20 * 1000 * 1000)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=0,instructions=[]):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)] + instructions
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,table_id=table_id, buffer_id=ofproto.OFP_NO_BUFFER)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.packetct += 1
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

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_udp = pkt.get_protocol(udp.udp)

        # send the packet out. Also happens to all non udp packets.
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        print("sending packet out...")
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
