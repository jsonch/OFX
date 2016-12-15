#
# OFX based declassifier control application. 
# 1) load the OFX declassification module.
# 2) send the command to the switch to start the declassifier.
# 3) that's it?

import time
import pickle
import os
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

# grab the latest ofxLib version
import shutil
shutil.copy('../controller/ofxLib.py', "./")
import ofxLib

# silverline module location. 
silverlinemodulefile = '../modules/silverline/silverlineModule.py'

# ip address and port of the server thats protected by silverline.
serverIp = '10.0.0.2'
serverPort = 666

serverIp = '1.1.1.5' # for pica8 testbed

# port that the centralized declassifier database listens on. 
declassifierListenIp = '0.0.0.0'
declassifierListenPort = 55555


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # OFX startup: set the interface and give it control 
    # of all experimenter messages from the switch.
    ofxInterface = ofxLib.OfxInterface()
    @set_ev_cls(ofp_event.EventOFPExperimenter, MAIN_DISPATCHER)
    def switchMsgHandler(self, ev):
        self.ofxInterface.mainHandler(ev)

    # OFX startup: load the modules that you want onto the switch.
    ofxInterface.loadModule(silverlinemodulefile)
    # OFX startup: reference to the interface of the module you loaded.
    silverlineInterface = ofxInterface.loadedInterfaces['silverlineModule']


    def silverlineStartup(self, datapath):
        """
        silverline startup function: load the required permissions.
        Send them to the switch, or store them locally or whatever.
        """
        flowkeys = pickle.load(open("flowinfo.pkl", "r"))
        time.sleep(8)
        print ("sending %s permissions to switch."%len(flowkeys))
        for flow in flowkeys:
            dstip, srcip, dstport, srcport = flow
            src = srcip
            dst = dstip
            sport = struct.pack("!H", srcport)
            dport = struct.pack("!H", dstport)
            permission = struct.pack("!i", 1)
            msg = src + dst + sport + dport + permission
            self.silverlineInterface.addFlowPermission(datapath.send, msg)
            time.sleep(4.5/1000) # about how long it takes to add a permission on a pica8.            
        print ("sent all %s permissions to switch."%len(flowkeys))

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_port = {}
        self.packetct = 0
        self.activeDatapaths = []
        # hub.spawn(self.declassifierLoop)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print ("a switch connected.")
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
        # match = parser.OFPMatch()
        # actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        # #                                   ofproto.OFPCML_NO_BUFFER)]
        # self.add_flow(datapath, 0, match, actions)

        # OFX: push loaded modules down to this switch. (i.e. silverline)
        self.ofxInterface.pushModulesToSwitch(datapath.send)

        # OFX: enable declassifier on this switch.
        self.silverlineInterface.enableDeclassifier(datapath.send)

        # add the real routing rules to table 1.
        match = parser.OFPMatch(eth_dst="00:00:00:00:00:01")
        actions = [parser.OFPActionOutput(2)]
        self.add_flow(datapath, 0, match, actions, table_id=1)

        match = parser.OFPMatch(eth_dst="00:00:00:00:00:02")
        actions = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 0, match, actions, table_id=1)

        # add the goto rule that sends packets from 666 to table 1.
        match = parser.OFPMatch(in_port=666)
        instructions = [parser.OFPInstructionGotoTable(1)]
        actions = []
        self.add_flow(datapath, 2, match, actions, table_id=0, instructions=instructions)


        # # silverline: don't touch packets going _to_ the server. 
        # # only packets coming out.
        # actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # match = parser.OFPMatch(ipv4_dst=serverIp, eth_type=0x0800, ip_proto=0x11, udp_dst=serverPort)
        # self.add_flow(datapath, 2, match, actions)
        # keep a list of the active data path objects, so you can easily
        # send stuff to them. 
        self.activeDatapaths.append(datapath)
        self.silverlineStartup(datapath)


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
                                    match=match, instructions=inst,table_id=table_id)
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

    def declassifierLoop(self):
        """
        open a socket and listen for flow permission messages.
        When you get a new flow permission message, 
        send a message to all the switches adding the permission 
        to their local table via an OFX silverline message.
        """
        print ("opening socket.")
        ADDR = (declassifierListenIp, declassifierListenPort)
        declassifierSocket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        declassifierSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        declassifierSocket.bind(ADDR)
        declassifierSocket.listen(5)
        while True:
            print ("waiting for new connection from silverline server.")
            conn, addr = declassifierSocket.accept()
            print ("socket connected.")
            while True:
                data = self.recv_n_bytes(16, conn)
                if data == None:
                    print ("SOCKET TO SERVER CLOSED.")
                    break
                src = data[0:4]
                dst = data[4:8]
                sport = struct.unpack("!H", data[8:10])[0]
                dport = struct.unpack("!H", data[10:12])[0]
                permission = struct.unpack("!i", data[12::])[0]
                # forward the data to all the switches with an OFX message.
                for datapath in self.activeDatapaths:
                    self.silverlineInterface.addFlowPermission(datapath.send, data)

    def recv_n_bytes(self, n, socket):
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


