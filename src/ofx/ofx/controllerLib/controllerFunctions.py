"""
Common controller functions that are useful in test apps.
Can't import this. Need to copy/paste for now.
"""

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

