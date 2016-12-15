/***************************************************************
 * reads a raw ethernet packet from one tap interface and 
 * sends it back out another. Assumes the interface is online. 
 * (i.e. "ip link set up tapX" was used). If not, see the commented 
 * examples for reading / writing with a tap device file descriptor.
 ***************************************************************/

#include <stdio.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <dlfcn.h>
#include  <signal.h>
#include <stdint.h>
#include <pthread.h>

// Definitions for data path <--> agent communication.
#define OFXHEADERLEN 12
struct ofxDpHeader {
    uint32_t len;
    uint32_t moduleId;
    uint32_t messageType;
};
// OFX system messages (datapath agent < -- > management agent)
#define OFXSYSMODULEID 0x1 // ID for OFX system messages.
// Message Types:
// Add UDP flow
#define UDPFLOWMSGTYPE 0x1
#define UDPADDFLOWLEN 12
struct udpFlowMessage {
    struct  in_addr ip_src,ip_dst;
    u_short uh_sport, uh_dport;
};
int addUDPCountingFlow(struct in_addr ip_src, struct in_addr ip_dst, 
    u_short sport, u_short dport);
// Add DSCP flow
#define DSCPFLOWMSGTYPE 0x2
#define DSCPADDFLOWLEN 16
struct dscpFlowMessage {
    struct  in_addr ip_src,ip_dst;
    u_short uh_sport, uh_dport;
    uint32_t tos;
};
int addIpDscpFlow(struct in_addr ip_src, struct in_addr ip_dst, 
    u_short sport, u_short dport, uint32_t tos);
// Add a TCP flood flow.
#define TCPFLOWMSGTYPE 0x4
#define TCPADDFLOWLEN 12
struct tcpFlowMessage {
    struct  in_addr ip_src,ip_dst;
    u_short th_sport, th_dport;
};
int addTCPFloodFlow(struct in_addr ip_src, struct in_addr ip_dst, 
    u_short sport, u_short dport);
// Send a packet to the controller as a packet_in.
#define PACKETUP 0x3
int sendPacketUp(unsigned char * ethpkt, int pktlen);
// Send a message from the DP component of a module to the agent component.
sendMsgUp(unsigned char * msgcontents, int msgLen, int moduleId, int msgType);

// Buffers, etc.
char * msgBuffer; 
#define OFXMSGMAXLEN (1024*640)


// Other declarations.
int startAgentSocket();
void agentMessageRecvLoop(void *arg);


int switchSocket;
int dpConnection = -1;

// Path of the packet handling library, and name of the 
// packet handling function.
char * modulefn = "./ofxmodule.so";
char * handlefcnname = "handle_packet";
char * startupfcnname = "module_startup";
char * msgfcnname = "handle_message";

// A reference to the packet handler module, packet processing function, 
// and startup function.
void * modulelib = NULL;
int (*handleFcn)(unsigned char* ethpkt, unsigned char* ippkt, int pktsize);
int (*startupFcn)();
int (*msgFcn)(struct ofxDpHeader * msgHeader, unsigned char* msg);

// Reloads the module containing user code.
// (including packet handler function and startup function)
void reload_module(){
    dprint("in reload module.\n");
    modulelib = dlopen(modulefn, RTLD_LAZY);
    if (!modulelib){
        dprint("shared library not loaded.\n");
        dprint("\t(tried to open %s)\n",modulefn);
        char * errorstr = dlerror();
        dprint("\t--%s--\n",errorstr);
        exit(1);            
    }
    handleFcn = dlsym(modulelib, handlefcnname);
    if (!handleFcn){
        dprint("shared function not loaded.\n");
        exit(1);            
    }
    startupFcn = dlsym(modulelib, startupfcnname);
    if (!startupFcn){
        dprint("startup function not loaded.\n");
        exit(1);
    }
    msgFcn = dlsym(modulelib, msgfcnname);
    if (!msgFcn){
        dprint("message function not loaded.\n");
        exit(1);
    }

    // Call the startup function that you just loaded.
    startupFcn();
    dprint("returned from startup function.\n");
}

// Reloads the linked library on sigalarm.
void  ALARMhandler(int sig)
{
  dprint("entered sigALARM handler.\n");
  signal(SIGALRM, SIG_IGN);          /* ignore this signal       */
  if (modulelib != NULL){
    dlclose(modulelib);
  }
  reload_module();
  signal(SIGALRM, ALARMhandler);     /* reinstall the handler    */
}

void intHandler(int sig)
{
    dprint("got sigint.. ignoring.\n");

}
#define ETHER_ADDR_LEN  6
#define SIZE_ETHERNET 14
/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};


#define MPLS_ETHER_TYPE 0x8847
#define MPLS_OFFSET 18 // inner packet starts at size_ethernet + 4
#define SIZE_MPLS 4

/* mpls shim */
struct mpls_shim {
    uint32_t value;
    #define MPLS_LABEL_MASK  0xfffff000
    #define MPLS_LABEL_SHIFT 12
    #define MPLS_EXP_MASK    0x00000e00
    #define MPLS_EXP_SHIFT   9
    #define MPLS_STACK_MASK  0x00000100
    #define MPLS_STACK_SHIFT 8
    #define MPLS_TTL_MASK    0x000000ff
    #define MPLS_TTL_SHIFT   0
    #define MPLS_LABEL(x)   (((x) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT)
    #define MPLS_EXP(x) (((x) & MPLS_EXP_MASK) >> MPLS_EXP_SHIFT)
    #define MPLS_STACK(x)   (((x) & MPLS_STACK_MASK) >> MPLS_STACK_SHIFT)
    #define MPLS_TTL(x) (((x) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT)
};
 

FILE *logfile;
void dprint(char* str, ...){
    va_list args;
    va_start(args,str);
    char logline[1024];
    vsprintf(logline, str, args);
    va_end(args);

    time_t ltime; /* calendar time */
    ltime=time(NULL); /* get current cal time */
    fprintf(logfile, "%i: %s",(int)ltime,logline);
    fflush(logfile);
}

int main(int argc, char *argv[])
{
    if (argc != 4){
        dprint("Wrong number of arguments. (3 required, %u given)\n",argc);
        return 0;
    }
    signal(SIGINT, intHandler); // ignore sigints, for convenience 
    // when using mininet.
    char devicename[10];
    strcpy(devicename, argv[1]);
    char switchname[10];
    strcpy(switchname, argv[2]);
    int switchAgentPort = atoi(argv[3]);

    char logfilename[128];
    sprintf(logfilename, "%s-dpagent.log",switchname);
    logfile = fopen(logfilename, "w");
    dprint("log file opened..\n");
    dprint("starting generic DP agent.\n");
    int nread;
    int nwrite;
    #define BUFSIZE 1614
    unsigned char buffer[BUFSIZE];

    // buffer for messages to OFX management agent.
    msgBuffer = calloc(1, OFXMSGMAXLEN);

    startAgentSocket(switchAgentPort);
    dprint("loading module.\n");
    // set up handler for the signal that indicates
    // code has changes.
    signal(SIGALRM, ALARMhandler);
    reload_module();
        

    dprint("opening socket to datapath.\n");
    int sd = create_rawsocket(ETH_P_ALL);
    dprint ("binding to INPUT interface %s (via socket)\n",devicename);
    int ret = bind_rawsocket(devicename, sd, ETH_P_ALL);

    dprint ("starting listening loop.\n");
    // variables for the loop.
    int action;
    int i;
    while (1)
    {
        nread = recv_rawpacket(sd, buffer, BUFSIZE);
        struct sniff_ethernet *ethernet;  // Ethernet header
        ethernet = (struct sniff_ethernet*)(buffer);
        // We can either: only handle packets with the IP ecn bit set.
        // Or, make sure flood doesn't send packets out of the
        // port registered for OFX. (rewrite flood commands)
        // dprint("got a packet..\n");
        action = handleFcn(buffer, buffer+SIZE_ETHERNET, nread);
        // if action is 0, drop the packet. otherwise, send the packet back out.
        switch (action){
            case 0: // returns 0: drop packet.
                // dprint("DP Agent dropping packet.\n");
                break;
            default: // returns anything else: send packet back to data path.
                // note: the packet will still keep the module's mpls id on it.
                // dprint("DP Agent sending packet back to switch.\n");
                // mpls->value = htonl(mpls->value);                    
                // dprint("\tsending packet out. \n\tmpls label final: %i\n",mpls->value);
                send_rawpacket(sd, buffer, nread);
                break;
            // // example: overwrite MPLS header with another value.
            //     // Zero out bits >20
            //     masked_label = (action&0x000fffff);
            //     // Position bits correctly.
            //     shifted_label = masked_label<<MPLS_LABEL_SHIFT;
            //     // Overwrite existing value with new label and other existing bits.
            //     mpls->value = (mpls->value & 0x00000fff) | shifted_label;
            //     // dprint("modified MPLS field as host ordered hex: %08x\n", mpls->value);
            //     // change back to network ordering.
            //     mpls->value = htonl(mpls->value);
            //     dprint("\tDP Agent returning packet with relabeled MPLS %u\n",action);
            //     // dprint("MPLS shim bytes MODIFIED: ");
            //     // for (i = SIZE_ETHERNET; i < SIZE_ETHERNET+4; i++) {
            //     //     dprint("%02X ",buffer[i]);
            //     // }
            //     // dprint("\n");
            //     // send the packet with its modified MPLS shim.
            //     send_rawpacket(sd, buffer, nread);
            //     break;
        }
    
    }
}


// create a raw socket.
int create_rawsocket(int protocol_to_sniff)
{
    int rawsock;
    if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
    {
        perror("Error creating raw socket: "); exit(-1);
    }
return rawsock; 
}

// bind to a raw socket.
int bind_rawsocket(char *device, int rawsock, int protocol) 
{
    struct sockaddr_ll sll;
    struct ifreq ifr;
    bzero(&sll, sizeof(struct sockaddr_ll));
    bzero(&ifr, sizeof(struct ifreq));
    /* First Get the Interface Index */
    strncpy((char *)ifr.ifr_name, device, IFNAMSIZ); 
    if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
    {
        dprint("Error getting Interface index !\n"); 
        exit(-1); 
    }
    /* Bind our raw socket to this interface */
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(protocol);
    if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
    {
        perror("Error binding raw socket to interface\n"); 
        exit(-1);
    }
    return 1; 
}

// get data in on a raw socket.
int recv_rawpacket(int rawsock, unsigned char *pkt, int pkt_len)
{
    int recv= 0;
    recv = read(rawsock, pkt, pkt_len); 
    return recv;
}
// send data out on a raw socket.
int send_rawpacket(int rawsock, unsigned char *pkt, int pkt_len)
{
    int sent= 0;
    if((sent=write(rawsock, pkt, pkt_len)) != pkt_len)
    {

        if (sent == -1){
            perror("socket write error.\n");
            exit(-1);
        }
        dprint("Could only send %d bytes of packet of length %d\n", sent, pkt_len);
        return 0; 
    }
    return 1; 
}


// Functions to connect a socket to the switch management agent, 
// for sending requests, etc.
int startAgentSocket(int switchAgentPort){
    int n;
    struct sockaddr_in serveraddr;
    char buf[BUFSIZE];
    sleep(2); // wait for the socket
    /* socket: create the socket */
    if ((switchSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
        dprint("socket() failed.\n");
        exit(0);
    }
    dprint("socket file descriptor: %i\n",switchSocket);


    /* build the server's Internet address */
    memset(&serveraddr, 0, sizeof(serveraddr));     /* Zero out structure */    
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serveraddr.sin_port = htons(switchAgentPort);
    // inet_aton("127.0.0.1", &serveraddr.sin_addr.s_addr);

    // dprint("\tip: %s\n",inet_ntoa((struct in_addr) serveraddr.sin_addr.s_addr));
    /* connect: create a connection with the server */
    while (dpConnection == -1){
        dpConnection = connect(switchSocket, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
        dprint("connection to agent failed. retrying.\n");
        sleep(1);
    }
    dprint("socket to Agent connected. fd: %i\n",switchSocket);
    /* start the socket recieve loop. */
    int err;
    pthread_t tid;
    err = pthread_create(&tid, NULL, &agentMessageRecvLoop, NULL);

    return 1;
}

// Get n bytes from a socket.
int recv_n_bytes(int sockfd, char *buf, int n){
    int bytesRecieved;
    int bytesLeft=n;
    int currentIdx=0;
    while (bytesLeft>0){
        bytesRecieved = recv(sockfd, buf+currentIdx, bytesLeft, 0);
        if (bytesRecieved == 0) return 0;
        bytesLeft = bytesLeft - bytesRecieved;
        currentIdx += bytesRecieved;
    }
    return n;

}

// Send a bytes in a buffer to a socket.
int send_all(int socket, void *buffer, size_t length)
{
    char *ptr = (char*) buffer;
    while (length > 0)
    {
        int i = send(socket, ptr, length, 0);
        if (i < 1) return 0;
        ptr += i;
        length -= i;
    }
    return 1;
}




void agentMessageRecvLoop(void *arg){
    char * agentMsgBuffer = calloc(1, OFXMSGMAXLEN);
    struct ofxDpHeader * msgHeader;    
    while (switchSocket<=0){
        dprint("WAITING ON switchSocket. %i\n",switchSocket);
        sleep(1);

    }
    while (1)
    {
        int retval = recv_n_bytes(switchSocket, agentMsgBuffer, 12);
        msgHeader = (struct ofxDpHeader *) agentMsgBuffer;
        msgHeader->len = (uint32_t) ntohl(msgHeader->len);
        msgHeader->moduleId = (uint32_t) ntohl(msgHeader->moduleId);
        msgHeader->messageType = (uint32_t) ntohl(msgHeader->messageType);
        // Get the rest of the message.
        retval = recv_n_bytes(switchSocket, agentMsgBuffer+12,msgHeader->len-12);
        // call the handler function, just of the single loaded module, 
        // for now.
        msgFcn(msgHeader, agentMsgBuffer+12);
    }
}


int addUDPCountingFlow(struct in_addr ip_src, struct in_addr ip_dst, 
    u_short sport, u_short dport){
    // dprint("dp agent got a request to install a udp counting rule.\n");
    memset(msgBuffer, 0, OFXMSGMAXLEN);

    // Build the inner message: a request to add a flow.
    struct udpFlowMessage * newFlow = (struct udpFlowMessage *)(msgBuffer+OFXHEADERLEN);
    newFlow->ip_src = ip_src;
    newFlow->ip_dst = ip_dst;
    newFlow->uh_sport = sport;
    newFlow->uh_dport = dport;

    // Build the outer OFX headers.
    struct ofxDpHeader * msg = (struct ofxDpHeader *)(msgBuffer);
    msg->messageType = htonl(UDPFLOWMSGTYPE);
    msg->moduleId = htonl(OFXSYSMODULEID);
    msg->len=htonl(OFXHEADERLEN + UDPADDFLOWLEN);

    //Send the data.
    int result = send_all(switchSocket, msg, ntohl(msg->len));
    return result;    

}

int addIpDscpFlow(struct in_addr ip_src, struct in_addr ip_dst, 
    u_short sport, u_short dport, uint32_t tos){
    memset(msgBuffer, 0, OFXMSGMAXLEN);

    // Build the inner message: a request to add a flow.
    struct dscpFlowMessage * newFlow = (struct dscpFlowMessage *)(msgBuffer+OFXHEADERLEN);
    newFlow->ip_src = ip_src;
    newFlow->ip_dst = ip_dst;
    newFlow->uh_sport = sport;
    newFlow->uh_dport = dport;
    newFlow->tos = tos;
    // Build the outer OFX headers.
    struct ofxDpHeader * msg = (struct ofxDpHeader *)(msgBuffer);
    msg->messageType = htonl(DSCPFLOWMSGTYPE);
    msg->moduleId = htonl(OFXSYSMODULEID);
    msg->len=htonl(OFXHEADERLEN + DSCPADDFLOWLEN);

    //Send the data.
    int result = send_all(switchSocket, msg, ntohl(msg->len));
    return result;    

}
// Send a bytestring to the management agent.
int sendMsgUp(unsigned char * msgcontents, int msgLen, int moduleId, int msgType){
    // dprint("sending message to management agent.\n");
    memset(msgBuffer, 0, OFXMSGMAXLEN);
    // Build the outer OFX headers.
    struct ofxDpHeader * msg = (struct ofxDpHeader *)(msgBuffer);
    msg->moduleId = htonl(moduleId);
    msg->messageType = htonl(msgType);
    msg->len=htonl(OFXHEADERLEN + msgLen);
    // Copy message to buffer.
    memcpy(msgBuffer+OFXHEADERLEN, msgcontents, msgLen);
    int result = send_all(switchSocket, msg, ntohl(msg->len));
    return 1;    
}


// for avantguard: send a packet to the controller.
// Strip the MPLS header first.
#define PACKETUP 0x3
int sendPacketUp(unsigned char * ethpkt, int pktlen){
    // dprint("sending a packet up to the controller (len: %i).\n",pktlen);
    memset(msgBuffer, 0, OFXMSGMAXLEN);

    // Build the inner message: a request to add a flow.
    // Build the outer OFX headers.
    struct ofxDpHeader * msg = (struct ofxDpHeader *)(msgBuffer);
    msg->messageType = htonl(PACKETUP);
    msg->moduleId = htonl(OFXSYSMODULEID);
    msg->len=htonl(OFXHEADERLEN + pktlen);
    // Copy packet eth header to buffer.
    memcpy(msgBuffer+OFXHEADERLEN, ethpkt, SIZE_ETHERNET);
    // Set eth type to IP
    struct sniff_ethernet * ethheader = (struct sniff_ethernet *) (msgBuffer+OFXHEADERLEN);
    ethheader->ether_type=htons(0x0800);
    // Skip the mpls header and copy the rest of the packet to the buffer.
    memcpy(msgBuffer+OFXHEADERLEN+SIZE_ETHERNET, 
        ethpkt+SIZE_ETHERNET+SIZE_MPLS,
        pktlen-SIZE_ETHERNET-SIZE_MPLS);
    //Send the data.
    int result = send_all(switchSocket, msg, ntohl(msg->len));
    return result;    

}


int addTCPFloodFlow(struct in_addr ip_src, struct in_addr ip_dst, 
    u_short sport, u_short dport){

    memset(msgBuffer, 0, OFXMSGMAXLEN);

    // Build the inner message: a request to add a flow.
    struct tcpFlowMessage * newFlow = (struct tcpFlowMessage *)(msgBuffer+OFXHEADERLEN);
    newFlow->ip_src = ip_src;
    newFlow->ip_dst = ip_dst;
    newFlow->th_sport = sport;
    newFlow->th_dport = dport;

    // Build the outer OFX headers.
    struct ofxDpHeader * msg = (struct ofxDpHeader *)(msgBuffer);
    msg->messageType = htonl(TCPFLOWMSGTYPE);
    msg->moduleId = htonl(OFXSYSMODULEID);
    msg->len=htonl(OFXHEADERLEN + TCPADDFLOWLEN);

    //Send the data.
    int result = send_all(switchSocket, msg, ntohl(msg->len));
    return result;    

}

// End methods that should be exported to the data path agent.

