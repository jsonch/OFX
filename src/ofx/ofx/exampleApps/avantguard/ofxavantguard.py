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
from ryu.lib.packet import tcp
from ryu.lib import hub 
import socket
import struct


from ryu.ofproto import ofproto_v1_3_parser 
# grab the latest ofxLib version
import shutil
shutil.copy('../controller/ofxLib.py', "./")
import ofxLib

# silverline module location. 
avantguardmodule = '../modules/avantguard/avantguardModule.py'


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
    ofxInterface.loadModule(avantguardmodule)
    # OFX startup: reference to the interface of the module you loaded.
    avantGuardInterface = ofxInterface.loadedInterfaces['avantguardModule']


    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_port = {}
        self.packetct = 0
        self.activeDatapaths = []


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
        # new default: flood.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        #                                   ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # OFX: push loaded modules down to this switch. (i.e. silverline, botminer, etc)
        self.ofxInterface.pushModulesToSwitch(datapath.send)

        # enable TCP connection validation on this switch.
        self.avantGuardInterface.enableConnectionValidation(datapath.send)

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
        print ("got packet in (# %s)"%self.packetct)
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
        src = pkt_ipv4.src
        dst = pkt_ipv4.dst
        # print ("packet info: %s --> %s"%(src, dst))
        pkt_udp = pkt.get_protocol(udp.udp)
        # if its a udp packet, run declassifier logic.

        # send the packet out. Also happens to all non udp packets.
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # print("sending packet out...")
        data = None
        # print ("message buffer: %s"%msg.buffer_id)
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            # print ("\tno buffer.")
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        if not pkt_tcp:
            datapath.send_msg(out)
        else:
            sport = pkt_tcp.src_port
            dport = pkt_tcp.dst_port
            print ("\ttcp packet.")
            # print ("tcp packet. adding 2 priority rules for flow.")
            # match = parser.OFPMatch(ipv4_src=src, ipv4_dst=dst, \
            #     eth_type=0x0800, ip_proto=0x06, tcp_src=sport, tcp_dst=dport)
            # actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            # self.add_flow(datapath, 10, match, actions)              
            # match = parser.OFPMatch(ipv4_src=dst, ipv4_dst=src, \
            #     eth_type=0x0800, ip_proto=0x06, tcp_src=dport, tcp_dst=sport)
            # actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            # self.add_flow(datapath, 10, match, actions)              

            # datapath.send_msg(out)
