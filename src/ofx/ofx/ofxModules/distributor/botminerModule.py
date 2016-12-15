"""
Botminer data collecting module. 
"""
import socket
import struct
import threading
import time
import cPickle as pickle

# Module ID, for OFX internal reference.
MODULEID = 0x30


# dependencies for this module
dependencies = ['uthash.h']

# message type definitions for this module. 
STARTCOLLECTION = 0x01 # controller -> switch: start collection.
# switch -> controller new data
NEWDATASTART = 0X02
NEWDATAPART = 0x03
NEWDATAFINISH = 0x04
DPAGENTUPDATE = 0x05


packetLen = 1450
# options for these experiments: 150, 350, 1450

class ControllerComponent(object):
    """
    The component that gets loaded by the controller.
    This provides an interface for control programs to use this module.
    """
    MODULEID = 0x30


    flowDictAsic = {}
    flowDictDp = {}

    def __init__(self, ofxControllerInterface):
        self.ofxSys = ofxControllerInterface
        # the handler for messages from the switch by this module.
        self.mainHandler = self.handleModuleMessage

    def startCollection(self, sendToSwitch, updatePeriod, switchId):
        """
        Start collecting data on the switch. 
        Switch will send back an update every updatePeriod seconds.
        """
        print ("enabling OFX botminer data collection on switch %s"%switchId)
        data = struct.pack("!i", updatePeriod)
        msg = self.ofxSys.buildModuleMessage(self.MODULEID, STARTCOLLECTION, data)
        sendToSwitch(msg)

    def handleModuleMessage(self, data, datapathSendFcn, datapathId):
        messageType, content = self.ofxSys.unpackModuleMessage(data)
        if messageType == NEWDATASTART:
            self.hostRecords = []
            self.flowRecords = []
        elif messageType == NEWDATAPART:
            self.handleSwitchUpdate(content, datapathSendFcn, datapathId)
        elif messageType == NEWDATAFINISH:
            self.finishSwitchUpdate(content, datapathSendFcn, datapathId)
        elif messageType == DPAGENTUPDATE:
            self.handleDpUpdate(content, datapathSendFcn, datapathId)

    def handleDpUpdate(self, data, datapathSendFcn, datapathId):
        """
        Handles an update of flows from the datapath.
        struct FlowKey{
    struct  in_addr ip_src,ip_dst;
    u_short uh_sport;
    u_short uh_dport;
};
struct FlowEntryNoHash{
    struct FlowKey key;
    uint32_t permission;
    uint32_t added; // Has the rule been added?
    uint32_t byteCt; // how many packets have we seen?
};
        """
        data = str(data)
        flowCt = len(data)/24
        print ("got info about %s flows from the datapath (switch id: %s)."%(flowCt, datapathId))
        idx = 0
        ptr = 0
        while idx<flowCt:
            ptr = idx * (24)
            src = socket.inet_ntoa(data[ptr:ptr+4])
            dst = socket.inet_ntoa(data[ptr+4:ptr+8])
            sport,dport = struct.unpack("!HH", data[ptr+8:ptr+12])
            permission,added,byteCt = struct.unpack("!III",data[ptr+12:ptr+24])
            # print ("DP AGENT flow %s: %s (%s) --> %s (%s) -- %s bytes"%(idx, src, sport, dst, dport, byteCt))

            key = (src,dst,sport,dport)
            if key not in self.flowDictDp:
                self.flowDictDp[key] = 0
            self.flowDictDp[key] =byteCt
            idx += 1
        self.botMiner()

    def handleSwitchUpdate(self, content, datapathSendFcn, datapathId):
        """
        Handle a statistics update from the switch.
        """
        print ("got data update from switch (%s bytes)"%len(content))  
        flowRecords = pickle.loads(str(content))
        idx = 0
        for r in flowRecords:
            src = socket.inet_ntoa(r[0:4])
            dst = socket.inet_ntoa(r[4:8])
            sport,dport = struct.unpack("!HH", r[8:12])
            byteCt = struct.unpack("!I", r[12::])[0]
            # packetCt = byteCt / packetLen
            # print ("ASIC flow %s: %s (%s) --> %s (%s) -- %s bytes"%(idx, src, sport, dst, dport, byteCt))

            key = (src,dst,sport,dport)
            self.flowDictAsic[key]= byteCt
            idx += 1



    def finishSwitchUpdate(self, content, datapathSendFcn, datapathId):
        # print ("got %s host records and %s flow records from switch.")

        self.botMiner()

    def botMiner(self):
        """
        null botMiner module.
        """
        totalByteCt = sum(self.flowDictAsic.values()) + sum(self.flowDictDp.values())       
        print ("sending %s byte records to botminer. (%s ASIC & %s OFX)"\
            %(totalByteCt, sum(self.flowDictAsic.values()), sum(self.flowDictDp.values())))
        # pickle.dump((self.flowDictAsic, self.flowDictDp), open("OfxBotminerFlows.pkl", "w"))



class SwitchComponent(object):
    """
    The component that gets loaded by the OFX agent on the switch.
    """
    MODULEID = 0x30
    # messages that this module wants to handle on the switch.
    def __init__(self, ofxAgent):
        # the OpenFlow messages this module wants to intercept.
        self.OFInterceptors = {}
        # self.OFInterceptors = {'ofp_packet_in':self.handlePacketInMessage}
        # the handler for messages directed to this module.
        self.mainHandler = self.handleModuleMessage
        self.dpHandler = self.handleDpMessage
        # the agent running on the switch that interfaces with the switch and controller.
        self.ofxAgent = ofxAgent
        # methods provided by the switch agent to send to the controller and switch.
        self.sendToSwitchFcn = ofxAgent.injectToSwitch
        self.sendToControllerFcn = ofxAgent.injectToController
        # socket to the data path component for this module.
        self.dpSocket = None

    def handleDpMessage(self, msgType, data):
        """
        Handles messages from the data path component.
        """
        flowCt = len(data)/24
        self.ofxAgent.dprint( "botminer message from data path: %s"%len(data))
        self.ofxAgent.dprint ("(%s flow statuses)"%(flowCt))
        # send the flow stats to the controller, 1k at a time.
        start = 0     
        while start < len(data):
            end = start + (1000*24)
            content = data[start:end]
            start += 1000*24
            self.ofxAgent.dprint ("sending up to 1000 flow statuses to controller. (%s bytes)"%len(content))
            msg = self.ofxAgent.buildModuleMessage(self.MODULEID, DPAGENTUPDATE, content)
            self.ofxAgent.injectToController(msg)

    def handleModuleMessage(self, data):
        """
        Handles messages directed to this module.
        """
        #self.ofxAgent.dprint ("got a message in silverline module.")
        (messageType, content) = self.ofxAgent.unpackModuleMessage(data)
        #self.ofxAgent.dprint "\tmessage type: %s"%messageType
        if messageType == STARTCOLLECTION:
            self.startCollection(content)
    def startCollection(self, content):
        """
        Start collecting data for botminer.
        """
        # start the polling and update thread. 
        interval = struct.unpack("!i", content)[0]
        self.ofxAgent.dprint ("polling ASIC for UDP flow info (interval = %s)"%interval)
        t = threading.Thread(target=self.dataCollectionThread, args=(interval,))
        t.start()
        # install a tap for udp traffic, using OFX.
        self.ofxAgent.dprint ("tapping UDP traffic for botminer.")
        matchPatternIn = "priority=1, dl_type=0x0800, ip_proto=17"
        self.ofxAgent.tapToDpAgent(matchPatternIn, self.MODULEID)

    def dataCollectionThread(self, interval):
        """
        Collects data from the OpenFlow component of the switch about what 
        flows are installed. Returns records to the controller.
        """
        self.ofxAgent.dprint ("starting botminer data collection thread with interval: %s"%interval)
        while True:
            flowStats = self.ofxAgent.getFlowStats(self.MODULEID)
            lines = flowStats.split('\n')
            flowrecs = lines[1:-1]
            self.ofxAgent.dprint("\tgot %s flow records."%len(flowrecs))
            # the records botminer wants: flow and host stats.
            flowStats = {}
            hostStats = {}
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
                    flowStats[flowKey] = {'pct':pct, 'bct':bct}
                    # update two records.
                    if src not in hostStats:
                        hostStats[src] = {'ips':set([]), 'ports':set([])}
                    if dst not in hostStats:
                        hostStats[dst] = {'ips':set([]), 'ports':set([])}
                    hostStats[src]['ips'].add(dst)
                    hostStats[src]['ports'].add(dport)
                    hostStats[dst]['ips'].add(src)
                    hostStats[dst]['ports'].add(sport)
            # compute all the host records. 
            # hostRecords = []
            # # self.ofxAgent.dprint ("host records:")
            # # self.ofxAgent.dprint ("------------------------")
            # for ip, data in hostStats.items():
            #     record = "%s, %s, %s"%(ip, len(data['ips']), len(data['ports']))
            #     # self.ofxAgent.dprint record
            #     # a record contains the number of IPs and ports the host 
            #     # connected to.
            #     hostRecords.append(record)
            # self.ofxAgent.dprint ("------------------------")
            flowRecords = []
            # self.ofxAgent.dprint ("flow records:")
            # self.ofxAgent.dprint ("------------------------")
            for key, stats in flowStats.items():
                recordBin = socket.inet_aton(key[0]) + socket.inet_aton(key[1]) + struct.pack("!H",key[2]) + struct.pack("!H",key[3]) + struct.pack("!I",int(stats['bct']))
                # record = "%s, %s, %s"%(str(key), stats['pct'], stats['bct'])
                # self.ofxAgent.dprint record
                # self.ofxAgent.dprint key
                flowRecords.append(recordBin)
                # self.ofxAgent.dprint record
                # a record contains the packet and byte count of the flow.
            # self.ofxAgent.dprint ("------------------------")
            self.ofxAgent.dprint ("sending  %s flow records to controller."\
                %(len(flowRecords)))
            
            msg = self.ofxAgent.buildModuleMessage(self.MODULEID, NEWDATASTART, '')
            self.ofxAgent.injectToController(msg)

            maxsendct = 500
            start = 0
            while start<len(flowRecords):             
                controlString = pickle.dumps(flowRecords[start:start+maxsendct]) 
                msg = self.ofxAgent.buildModuleMessage(self.MODULEID, NEWDATAPART, controlString)
                self.ofxAgent.injectToController(msg)
                start += maxsendct
            start = 0
            # while start<len(hostRecords):             
            #     controlString = pickle.dumps((hostRecords[start:start+maxsendct], []))   
            #     msg = self.ofxAgent.buildModuleMessage(self.MODULEID, NEWDATAPART, controlString)
            #     self.ofxAgent.injectToController(msg)
            #     start += maxsendct
            msg = self.ofxAgent.buildModuleMessage(self.MODULEID, NEWDATAFINISH, '')
            self.ofxAgent.injectToController(msg)
            # wait until the next interval.   
            time.sleep(interval)

    
    def testThread(self, interval):
        """
        sends a message to the controller, waits interval, repeats.
        """
        self.ofxAgent.dprint ("starting testThreat with %s"%interval)
        msg = self.ofxAgent.buildModuleMessage(self.MODULEID, NEWDATA, "trololo")
        self.ofxAgent.injectToController(msg)

