# OpenFlow controller implementation of botminer. 
# - install a rule for each flow
# - track of host activity: how many IPs and ports each source IP connects to
# - track flow activity: the bps and pps of each flow
# periodically collect the host and flow activity and then run the 
# clustering algorithm (which will just do nothing, atm)


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
import time
import cPickle as pickle
updateInterval = 1 # how frequently to re-run botminer.

packetLen = 1450
# options for these experiments: 150, 350, 1450

attackThreshold = 500.0
# low DDoS: alert when MPBS > 5
# medium DDoS: alert when MBPS > 50
# high DDoS: alert when MBPS > 500

"""
Quick test (random source addr / port to 666 @ 1.1.1.5)
h1 hping3 --udp --rand-source --destport 666 -i 1 1.1.1.5
"""

class SimpleSwitch13(app_manager.RyuApp):
    flowDictAsic = {}
    flowDictDp = {}
    lastTime = 0
    currentTime = 0
    lastPktCt = 0
    detected = False
    started = False

    def botminerThread(self):
        while True:
            self.botMiner()
            time.sleep(1)

    def botMiner(self):
        """
        null botMiner module.
        """
        totalPktCt = sum(self.flowDictAsic.values()) + sum(self.flowDictDp.values())   
        newPktCt = (totalPktCt-self.lastPktCt)
        self.lastPktCt = totalPktCt
        # print ("total packet ct: %s new: %s"%(totalPktCt, newPktCt))
        # print ("total dp packet ct: %s"%(sum(self.flowDictDp.values())))
        # print ("sending %s packets records to botminer. (%s ASIC & %s Controller)"\
        #     %(totalPktCt, sum(self.flowDictAsic.values()), sum(self.flowDictDp.values())))
        # pickle.dump((self.flowDictAsic, self.flowDictDp), open("OfBotminerFlows.pkl", "w"))
        # how many MBPS since last time?
        # just assume we're dealing in second update intervals.
        mbps = (newPktCt * 8.0 * 1450) / 1000 / 1000
        # mbitCt = (totalPktCt-self.lastPktCt) * 1450.0 * 8 / 1000 / 1000
        # self.currentTime = time.time()        
        # mbps =  mbitCt / (self.currentTime - self.lastTime)

        if mbps>0:
            if not self.started:
                self.started = True
                self.attackStart = time.time()
                print ("attack started at %s"%(self.attackStart))
        print ("%s"%mbps)
        if mbps>attackThreshold:
            if not self.detected:
                self.attackDetected = time.time()
                self.detected = True
            print ("ATTACK DETECTED in %s seconds"%(self.attackDetected-self.attackStart))
        self.lastTime = time.time()
        self.lastPktCt = totalPktCt

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def botminer_init(self):
        self.hostStats = {}
        self.flowStats = {}
        self.installedFlowMatches = [] # flow rules to query.
        # need to spawn a thread that:
        print ("spawning flow stats loop.")
        hub.spawn(self.flowStatLoop)
        hub.spawn(self.botminerThread)
        # 1) collects the flow stats data from the switch
        # 2) calls the ML function that does the mining
        # hub.spawn(self.declassifierLoop)


    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_port = {}
        self.packetct = 0
        self.activeDatapaths = []
        self.botminer_init()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print ("switch connected.")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the routing rules in table 1.
        match = parser.OFPMatch(in_port=1)
        # actions = [parser.OFPActionOutput(ofproto_v1_3.OFPP_IN_PORT)]
        actions = [parser.OFPActionOutput(2)]
        self.add_flow(datapath, 0, match, actions, table_id=1)

        # install the default rule.        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # instructions = [parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath, 0, match, actions)


        # match = parser.OFPMatch()
        # actions = []
        # instructions = [parser.OFPInstructionGotoTable(2)]
        # self.add_flow(datapath, 0, match, actions, instructions = instructions)

        # match = parser.OFPMatch(in_port=1)
        # actions = [parser.OFPActionOutput(ofproto_v1_3.OFPP_IN_PORT), parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        # self.add_flow(datapath, 0, match, actions, table_id=2)

        # match = parser.OFPMatch(in_port=2)
        # actions = [parser.OFPActionOutput(ofproto_v1_3.OFPP_IN_PORT), parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        # self.add_flow(datapath, 0, match, actions, table_id=2)



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
            # install a flow rule. 
            match = parser.OFPMatch(ipv4_src=src, ipv4_dst=dst, eth_type=eth.ethertype, \
                ip_proto=0x11, udp_src=sport, udp_dst=dport, ip_dscp=dataid)
            # actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            # self.add_flow(datapath, 10, match, actions)

            key = (src, dst, sport, dport)
            # print("adding flow for: %s (%s) -> %s (%s)"%key)

            if key not in self.flowDictDp:
                self.flowDictDp[key] = 0
            self.flowDictDp[key] +=1
            instructions = [parser.OFPInstructionGotoTable(1)]
            actions = []
            self.add_flow(datapath, 10, match, actions, table_id=0, instructions=instructions)
            self.installedFlowMatches.append((datapath, match))




    def flowStatLoop(self):
        """
        Query the switch for flow statistics.
        """
        while True:
            if len(self.installedFlowMatches)>0:
                datapath = self.installedFlowMatches[0][0]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                match = parser.OFPMatch()        
                msg = parser.OFPFlowStatsRequest(datapath, match=match)
                datapath.send_msg(msg)
                # for datapath, match in self.installedFlowMatches:
                #     ofproto = datapath.ofproto
                #     parser = datapath.ofproto_parser
                #     msg = parser.OFPFlowStatsRequest(datapath, match=match)
                #     datapath.send_msg(msg)
            time.sleep(updateInterval)
            # now collect all the records and call botminer.
            # self.botMiner()

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Collect the statistics response messages from the switch.
        """
        flows = []

        for stat in ev.msg.body:
            match = stat.match
            if 'ipv4_src' in match and \
            'ipv4_dst' in match and \
            'udp_src' in match and \
            'udp_dst' in match:
                key = (match['ipv4_src'], match['ipv4_dst'], match['udp_src'], match['udp_dst'])
                pct = stat.packet_count
                bct = stat.byte_count
                if key not in self.flowDictAsic:
                    self.flowDictAsic[key] = 0
                self.flowDictAsic[key] = bct / packetLen


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

