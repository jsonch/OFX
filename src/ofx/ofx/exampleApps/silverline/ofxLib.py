"""
controller interface to the OFX modules running on the switch.
"""
import importlib
import sys
import shutil
import glob
import struct
import cPickle as pickle
import twink.ofp4.build as ofbuild
import twink.ofp4.parse as ofparse
import twink.ofp4.oxm as oxm


# The OFX protocol:
# OFX messages are subtypes of the OpenFlow Experimenter message type.
# The experimenter message has three fields, which we set as follows:
# Experimenter ID: 
#     always 0x1 to represent an OFX message
# Experimenter type: 
#     0xffffffff:     OFX control message
#     0x0:0xffff:     OFX module ID.
# Data:
#     First 32 bits:  Message Type code (module dependent)
#     2nd 32 bits:    length of remainder of message.
#     Remainder:      Message (python pickleObject)


# OFX management message types:
#     0x1             load module


# OFX constants.
OFX_MESSAGE=0x1
OFX_MANAGEMENT_MODULE=0xffffffff

# OFX management message types.
# start message, send files, end message.
OFX_LOAD_MODULE_START=0x1 # payload: string containing module name.
OFX_LOAD_MODULE_FILE=0x2 # payload: pickled tuple: (filename, contents)
OFX_LOAD_MODULE_END=0x3 # payload: import and compilation instructions.
OFX_LOAD_MODULE_FILE_PIECE=0x4 # payload: pickled tuple: (filename, total len, contents)


class OfxInterface(object):
    def __init__(self):
        self.loadedInterfaces = {}
        self.loadedModuleBins = {}
        self.loadedDatapathBins = {}
        self.loadedDependencyBins = {}
        self.moduleHandlers = {}

    ##### functions the control application calls. ####
    def loadModule(self, moduleFile):
        """
        Loads an OFX module into memory. 
        Then, when a switch connects, it sends the module down 
        to the switch.
        """
        # copy the module to the current directory.
        moduleDir = "/".join(moduleFile.split("/")[0:-1])
        for f in glob.glob(moduleDir+"/*"):
            print f                                                                                                                                        
            shutil.copy(f, "./")
        moduleName = moduleFile.split("/")[-1][0:-3]

        print "loading OFX module: %s"%moduleName
        moduleObj = importlib.import_module(moduleName)
        newComponent = moduleObj.ControllerComponent(self)
        # load the controller interface.
        self.loadedInterfaces[moduleName] = newComponent
        # load the handler for messages of this module @ controller.
        self.moduleHandlers[newComponent.MODULEID] = newComponent.mainHandler
        # load the code for the switch agent.
        with open(moduleFile, "r") as f:
            moduleBin = f.read()        
        self.loadedModuleBins[moduleName] = moduleBin
        # load the code that will link into the datapath agent.
        with open(moduleFile[:-3]+".c", "r") as f:
            datapathBin = f.read()
        self.loadedDatapathBins[moduleName] = datapathBin        
        # load dependencies.
        self.loadedDependencyBins[moduleName] = {}
        for dep in moduleObj.dependencies:
            with open(dep, "r") as f:
                depBin = f.read()                
            self.loadedDependencyBins[moduleName][dep] = depBin


    #### functions a module can call. ####
    def buildModuleMessage(self, moduleId, messageType, content):
        """
        Build a message for a running module. 
        """
        contentLen = len(content)
        msg = struct.pack('!i', messageType)
        msg += struct.pack('!i', contentLen)
        msg += content
        data = self.buildOFXMessage(moduleId, msg)
        return data        

    def buildOFXMessage(self, moduleId, content):
        """
        Builds an OFX message to send to a OFX agent.
        Content is the binary content to send with the message.
        """
        data = ofbuild.ofp_experimenter_header(None,OFX_MESSAGE, moduleId, content)
        return data
    def buildOFXManagementMessage(self, messageType, content):
        """
        Builds an OFX management message to send to an OFX agent.
        Content is the binary content to send with the message.        
        """
        contentLen = len(content)
        msg = struct.pack('!i', messageType)
        msg += struct.pack('!i', contentLen)
        msg += content
        data = self.buildOFXMessage(OFX_MANAGEMENT_MODULE, msg)
        return data
    def unpackModuleMessage(self, data):
        """
        Unpacks an OFX message.
        """
        messageType = struct.unpack("!i", data[0:4])[0]
        dataLen = struct.unpack("!i", data[4:8])[0]
        return (messageType, data[8:8+dataLen])
    def pushModulesToSwitch(self, sendMsgToSwitchFcn):
        """
        pushes the loaded modules down a switch, using the controller 
        provided function.
        """
        for moduleName in self.loadedModuleBins.keys():
            print ("pushing module %s to switch"%moduleName)
            # start the transfer.
            msg = self.buildOFXManagementMessage(OFX_LOAD_MODULE_START, moduleName)
            sendMsgToSwitchFcn(msg)
            # send the python file.
            bin = self.loadedModuleBins[moduleName]
            sendString = pickle.dumps((moduleName+".py", bin))          
            msg = self.buildOFXManagementMessage(OFX_LOAD_MODULE_FILE, sendString)
            sendMsgToSwitchFcn(msg)
            # send the c file. 
            bin = self.loadedDatapathBins[moduleName]
            sendString = pickle.dumps((moduleName+".c", bin))          
            msg = self.buildOFXManagementMessage(OFX_LOAD_MODULE_FILE, sendString)
            sendMsgToSwitchFcn(msg)
            # send the dependencies. Send 32kb at a time. All transfers should do this.
            for dep, bin in self.loadedDependencyBins[moduleName].items():
                print ("sending file %s"%dep)
                start = 0
                end = 10000
                remaining = len(bin)
                while remaining>0:
                    print ("remaining: %s"%remaining)
                    partialBin = bin[start:end]
                    content = pickle.dumps((dep, len(bin), partialBin))
                    msg = self.buildOFXManagementMessage(OFX_LOAD_MODULE_FILE_PIECE, content)
                    sendMsgToSwitchFcn(msg)                    
                    start += 10000
                    end += 10000
                    remaining -= 10000
            # end the transfer. Here, we would also pass instructions to compile 
            # anything that needs to be compiled on the switch.
            msg = self.buildOFXManagementMessage(OFX_LOAD_MODULE_END, '')
            sendMsgToSwitchFcn(msg)

    def mainHandler(self, data, datapathSendFcn):
        """
        handles experimenter messages from the switch.
        """
        self.handleOFXMessage(data, datapathSendFcn)

    def handleOFXMessage(self, data, datapathSendFcn):
        """
        Handles OFX messages (experimenter messages with appropriate 
        type code).
        """
        ofMessage = ofparse.parse(data)
        ofxModuleId = ofMessage.exp_type
        # if it goes to the OFX management module, send it there.
        if ofxModuleId==OFX_MANAGEMENT_MODULE:
            self.handleOFXManagementMessage(ofMessage.data, datapathSendFcn)

        # else, send it to whatever module's function is registered to handle the id.
        elif ofxModuleId in self.moduleHandlers:
            self.moduleHandlers[ofxModuleId](ofMessage.data, datapathSendFcn)

    def handleOFXManagementMessage(data, datapathSendFcn):
        """
        handle an OFX management message on the controller.
        """
        print ("not implemented.")