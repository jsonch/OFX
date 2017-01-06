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

import twink.ofp4.parse as ofparse

# ryu imports to add flows faster.
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser

import Queue


class OpenFlowProxy(object):
    # the OpenFlow events that you want to intercept. 
    OFInterceptors = {\
    'ofp_packet_in':[],\
    'ofp_packet_out':[],\
    'ofp_flow_mod':[],\
    'ofp_multipart_reply':[]\
    }
    
    # fake ryu datapath object, makes it easy to generate flow mod byte strings.
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

    def __init__(self, controllerIp, controllerPort, proxyIp, proxyPort):
        # Open the debug file.
        self.logf = sys.stdout
        # spawn the proxy to the OpenFlow controller and switch. Pass it your intercept methods for switch -> controller and controller -> switch.
        self.OFProxy = BaseProxy(controllerIp, controllerPort, proxyIp, proxyPort, self.interceptFromControlOF, self.interceptFromSwitchOF, self.dprint)
    def startProxy(self):
        self.OFProxy.startProxy()
        self.OFProxy.runProxy()

    def registerOFHandler(self, event_type, handler):
        self.OFInterceptors[event_type].append(handler)

    def handleOFMessage(self, data):
        """
        Handles OpenFlow messages.
        """    
        version = ord(data[0])
        messageType = ord(data[1])
        mlen = len(data)
        # self.dprint ("version: %s type: %s len: %s"%(version, messageType, mlen))
        # parse the openflow message.
        ofMessage = ofparse.parse(data)
        # get its type as text.
        ofMessageType = ofMessage.__class__.__name__
        # run it through all of the registered message interceptors.
        # return the message only if the interceptors return it.
        if ofMessageType in self.OFInterceptors:
            for fcn in self.OFInterceptors[ofMessageType]:
                data = fcn(data)            
            return data
        else:
            return data

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
        self.dprint ("message controller -> switch")
        if data != None:
            self.injectToSwitch(data)      

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

    # Example function to generate a flow mod and inject it to the switch.     
    def addIpFlow(self, src, dst, cookie=0):
        """
        adds a IP flow rule to the switch for counting. 
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
        printfcn = None):
        self.controllerIp = controllerIp
        self.controllerPort = controllerPort
        self.switchListenIp = switchListenIp
        self.switchListenPort = switchListenPort
        self.switchInterceptMethod = switchInterceptMethod
        self.controlInterceptMethod = controlInterceptMethod
        self.dprint = printfcn
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
        self.d1 = threading.Thread(target = self.forwardData, args = (self.switchSock, self.controllerSock, self.switchInterceptMethod, "s->c"))
        self.d2 = threading.Thread(target = self.forwardData, args = (self.controllerSock, self.switchSock, self.controlInterceptMethod, "c->s"))
        self.d1.start()
        self.d2.start()
        # time.sleep(5)
        # # start up the echo loop (Openflow version 1.3 echo messages) to keep the switch alive. 
        self.dprint("calling echo loop to keep switch alive.")
        echothread = threading.Thread(target = self.echoLoop, args = ())
        echothread.start()

    def runProxy(self):
        # run forwarding threads until both sides terminate. 
        self.d1.join()
        self.d2.join()
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

    # sends an openflow 1.3 echo message in a loop. This stops the switch from breaking the connection when it is overloaded.
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

def simpleHandler(messageBytes):
    print ("intercepted an OpenFlow packet in message.")
    return messageBytes

def main():
    controllerIp, controllerPort, proxyIp, proxyPort = sys.argv[1::]
    controllerPort = int(controllerPort)
    proxyPort = int(proxyPort)
    # initialize proxy. 
    prox = OpenFlowProxy(controllerIp, controllerPort, proxyIp, proxyPort)
    # register a handler for packet ins.
    prox.registerOFHandler("ofp_packet_in", simpleHandler)
    # run proxy. 
    prox.startProxy()

#
if __name__ == '__main__':
          main()  
