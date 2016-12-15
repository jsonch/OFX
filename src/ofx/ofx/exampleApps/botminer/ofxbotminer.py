# controller application that uses ofx botminer module.

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

base_ofx_dir = "../.."
# grab the latest ofxLib version and import.
import shutil
shutil.copy('%s/controllerLib/ofxLib.py'%base_ofx_dir, "./")
import ofxLib

# botminer ofx module location. 
botminermodulefile = '%s/ofxModules/botminer/botminerModule.py'%base_ofx_dir


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
        dpid = ev.msg.datapath.id
        self.ofxInterface.mainHandler(msg_bytes, datapath_send, dpid)

    # OFX startup: load the modules that you want onto the switch.
    ofxInterface.loadModule(botminermodulefile)
    # OFX startup: reference to the interface of the module you loaded.
    switchInterface = ofxInterface.loadedInterfaces['botminerModule']


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
        self.add_flow_with_instructions(datapath, 0, match, actions, table_id=1)

    def addReflectRules(self, parser, datapath):
        """
        Adds forwarding rules that reflect each packet. 
        (to the forwarding table that's independent of OFX)        
        """        
        match = parser.OFPMatch(in_port=1)
        actions = [parser.OFPActionOutput(ofproto_v1_3.OFPP_IN_PORT)]
        self.add_flow_with_instructions(datapath, 0, match, actions, table_id=1)

        match = parser.OFPMatch(in_port=2)
        actions = [parser.OFPActionOutput(ofproto_v1_3.OFPP_IN_PORT)]
        self.add_flow_with_instructions(datapath, 0, match, actions, table_id=1)


    def addOtherRules(self, datapath):
        """
        Other kinds of forwarding rules. 
        """
        pass
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        # add the real routing rules to table 1.
        # match = parser.OFPMatch(eth_dst="00:00:00:00:00:01")
        # actions = [parser.OFPActionOutput(1)]
        # self.add_flow_with_instructions(datapath, 0, match, actions, table_id=1)

        # match = parser.OFPMatch(eth_dst="00:00:00:00:00:02")
        # actions = [parser.OFPActionOutput(2)]
        # self.add_flow_with_instructions(datapath, 0, match, actions, table_id=1)

        # match = parser.OFPMatch(in_port=666, eth_dst="00:00:00:00:00:01")
        # actions = [parser.OFPActionOutput(1)]
        # self.add_flow_with_instructions(datapath, 0, match, actions, table_id=1)

        # match = parser.OFPMatch(in_port=666, eth_dst="00:00:00:00:00:02")
        # actions = [parser.OFPActionOutput(2)]
        # self.add_flow_with_instructions(datapath, 0, match, actions, table_id=1)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        print ("got a connection from a new switch (%s). Adding Flood rules."%dpid)
        # add forwarding rules that flood. Unrelated to OFX.
        self.addFloodRules(parser, datapath)

        # OFX: push loaded modules down to this switch. (i.e. silverline, botminer, etc)
        self.ofxInterface.pushModulesToSwitch(datapath.send)

        # OFX: enable data collection on this switch.
        self.switchInterface.startCollection(datapath.send, 10, dpid)



    def add_flow_with_instructions(self, datapath, priority, match, actions, instructions = [], table_id=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)] + instructions
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table_id)
        datapath.send_msg(mod)

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
        # if its a udp packet, run declassifier logic.

        # send the packet out. Also happens to all non udp packets.
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        print("sending packet out...")
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)