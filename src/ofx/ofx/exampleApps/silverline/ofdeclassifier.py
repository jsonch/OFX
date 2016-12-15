#
# Simple OpenFlow based declassifier for UDP packets. 
# 1) Install a default rule to match UDP traffic.
#    (also a slightly higher priority rule that allows traffic 
#    going _to_ the server to get through)
# 2) Read a DB file that the raw_server modifies 
#    to keep track of which data IDs each flow has access to.
# 3) When a new UDP packet comes out of the server:
#     1) find the flow in the DB, look up its permission 
#     2) if flow has permission to access the data ID of the packet,  
#        add a rule that allows any packet from that flow with that data ID.
#     3) if the packet has an ID that is not allowed, 
#        drop the packet and print out a message.

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
import struct
import socket
import cPickle as pickle


flowDataFile = "flowdata.csv"
serverIp = '10.0.0.2'
serverPort = 666

declassifierListenIp = '0.0.0.0'
declassifierListenPort = 55555

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def silverlineStartup(self):
        """
        Load in all the permissions. 
        """
        flowkeys = pickle.load(open("flowinfo.pkl", "r"))
        print ("loading %s permissions in controller."%len(flowkeys))
        for flow in flowkeys:
            dstip, srcip, dstport, srcport = flow
            srcip = socket.inet_ntoa(srcip)
            dstip = socket.inet_ntoa(dstip)
            bkey = (srcip, dstip, srcport, dstport)
            self.flowPermissions[bkey] = 1

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_port = {}
        self.packetct = 0
        self.activeDatapaths = []
        self.flowPermissions = {}
        self.silverlineStartup()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print "a switch connected."
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

        # add the real routing rules to table 1.
        match = parser.OFPMatch(eth_dst="00:00:00:00:00:01")
        actions = [parser.OFPActionOutput(1)]
        self.add_flow(datapath, 0, match, actions, table_id=1)

        match = parser.OFPMatch(eth_dst="00:00:00:00:00:02")
        actions = [parser.OFPActionOutput(2)]
        self.add_flow(datapath, 0, match, actions, table_id=1)


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
        # if ev.msg.msg_len < ev.msg.total_len:
        #     self.logger.debug("packet truncated: only %s of %s bytes",
        #                       ev.msg.msg_len, ev.msg.total_len)
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
        if pkt_udp:
            # print ("ip packet. src: %s dst: %s"%(pkt_ipv4.src, pkt_ipv4.dst))
            src = pkt_ipv4.src
            dst = pkt_ipv4.dst
            sport = pkt_udp.src_port
            dport = pkt_udp.dst_port
            dataid = int(pkt_ipv4.tos)>>2 # data id is in dscp field. 
            # print ("(packet # %s) udp from %s:%s to %s:%s"%\
            #     (self.packetct, src, sport, dst, dport))
            # find the flow in the DB.
            bkey = (src, dst, sport, dport)
            if bkey in self.flowPermissions:
                permission = self.flowPermissions[bkey]
                if permission != dataid:
                    # print ("Data ID on packet not allowed. Dropping.")
                    return
                else:
                    # print ("Data ID on packet is allowed. Adding rule and forwarding.")                    
                    # add a rule that lets packets out from the server to the 
                    # remote socket, as long as they have this dscp field.
                    match = parser.OFPMatch(ipv4_src=src, ipv4_dst=dst, eth_type=eth.ethertype, \
                        ip_proto=0x11, udp_src=sport, udp_dst=dport, ip_dscp=dataid)
                    # actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                    # put this as a high priority table 1 rule, but 
                    # make the action goto:1 (aka the routing table)
                    instructions = [parser.OFPInstructionGotoTable(1)]
                    actions = []
                    self.add_flow(datapath, 10, match, actions, table_id=0, instructions=instructions)
            else:
                return
                print ("flow key not in DB..")
                # print self.flowPermissions
                # print bkey

        # send the packet out. Also happens to all non udp packets.
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        else:
            data = msg.data
            msg.buffer_id = ofproto.OFP_NO_BUFFER
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def recv_n_bytes(self, n, socket):
        """
        recieve a fixed number of bytes from socket.
        """
        data = ''
        while len(data)< n:
            chunk = socket.recv(n - len(data))
            if chunk == '':
                break
            data += chunk
        return data

