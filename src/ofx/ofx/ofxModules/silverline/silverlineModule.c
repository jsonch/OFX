#include <pthread.h>
#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>

#include "uthash.h"

#define MODULEID 0x20

int permissionCt = 0;
struct timeval tv;

double current_time;
double last_time;

double getMsTime(){
	gettimeofday(&tv, NULL); // get current time
    // convert tv_sec & tv_usec to millisecond
	double time_in_mill = 
         (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000 ; 
    return time_in_mill;
}


// Port that this component listens on.
int portno = 44444;

// local function declarations. 
// (i.e. functions that OFX does not call directly.)
void* socketFunc(void *);
void  error(char *);

// #define dprintf(...) printf(__VA_ARGS__)


/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* dont fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* UDP header */
struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */

};

#define SIZE_UDP        8               /* length of UDP header */


int print_packet(struct sniff_ip* ip, struct sniff_udp* udp)
{
    printf("--------------------------------\n");
    /* print source and destination IP addresses and udp ports */
    printf("\tFrom: %s\n", inet_ntoa(ip->ip_src));
    printf("\tTo: %s\n", inet_ntoa(ip->ip_dst));
    printf("\tSrc port: %d\n", ntohs(udp->uh_sport));
    printf("\tDst port: %d\n", ntohs(udp->uh_dport));
    printf("--------------------------------\n");
}


// format for a new flow permission message from a remote source.
struct NewPermissionRequest{
	struct  in_addr ip_src;
	struct  in_addr ip_dst;
	u_short uh_sport;
	u_short uh_dport;
	uint32_t permission;
};

struct FlowKey{
	struct  in_addr ip_src,ip_dst;
	u_short uh_sport;
	u_short uh_dport;
};

// an entry in the hash table. Has a flow key and a permission int.
struct FlowEntry{
	struct FlowKey key;
	uint32_t permission;
	uint32_t added; // Has the rule been added?
	UT_hash_handle hh;
};

// The flow hash table.
struct FlowEntry* flow_HT;
int flowCt = 0;

// Add a flow to the flow hash table, if it doesn't already exist there.
int addFlowEntry(struct FlowEntry* newFlow){
	struct FlowEntry* existingFlow;
	HASH_FIND(hh, flow_HT, &newFlow->key, sizeof(struct FlowKey), existingFlow);
	if (existingFlow){
		return -1;
	}
	HASH_ADD(hh, flow_HT, key, sizeof(struct FlowKey), newFlow);
	flowCt += 1;
	return 1;
}

// Retrieve a flow from the flow hash table.
struct FlowEntry* getFlowEntry(struct FlowEntry* reqFlow){
	struct FlowEntry* existingFlow;
	HASH_FIND(hh, flow_HT, &reqFlow->key, sizeof(struct FlowKey), existingFlow);
	if (!existingFlow){
		return NULL;
	}
	return existingFlow;
}

// Build a flow entry from a udp packet and a permission.
struct FlowEntry* buildFlowEntry(struct sniff_ip* ip, struct sniff_udp* udp, uint32_t permission){
	struct FlowEntry* newFlow = calloc(1, sizeof(struct FlowEntry));
	newFlow->key.ip_src = ip->ip_src;
	newFlow->key.ip_dst = ip->ip_dst;
	newFlow->key.uh_sport = udp->uh_sport;
	newFlow->key.uh_dport = udp->uh_dport;
	newFlow->permission = permission;
	return newFlow;
}


// Build a flow entry from a NewPermissionRequest.
struct FlowEntry* buildFlowEntryFromPermission(struct NewPermissionRequest* flowPermission){
	struct FlowEntry* newFlow = calloc(1, sizeof(struct FlowEntry));
	newFlow->key.ip_src = flowPermission->ip_src;
	newFlow->key.ip_dst = flowPermission->ip_dst;
	newFlow->key.uh_sport = flowPermission->uh_sport;
	newFlow->key.uh_dport = flowPermission->uh_dport;
	newFlow->permission = ntohl(flowPermission->permission);
	newFlow->added = 0;
	return newFlow;
}

// Print out a flow entry.
int printFlowEntry(struct FlowEntry * flow){
	char src[32];
    char dst[32];
    strcpy(src,inet_ntoa(flow->key.ip_src));
    strcpy(dst,inet_ntoa(flow->key.ip_dst));  
	printf("\tFlow: %s (%i) --> %s (%i): Permission %i \n", 
		src, ntohs(flow->key.uh_sport), 
		dst, ntohs(flow->key.uh_dport), 
		ntohl(flow->permission));
}

// Print out a new permission entry.
int printNewPermissionRequest(struct NewPermissionRequest * flowPermission){
	char src[32];
    char dst[32];
    strcpy(src,inet_ntoa(flowPermission->ip_src));
    strcpy(dst,inet_ntoa(flowPermission->ip_dst));  
	printf("\t(new permission request) Flow: %s (%i) --> %s (%i): Permission %i \n", 
		src, ntohs(flowPermission->uh_sport), 
		dst, ntohs(flowPermission->uh_dport), 
		ntohl(flowPermission->permission));
}

// functions that the OFX agent calls.
int handle_packet(unsigned char * ethpkt, unsigned char * ippkt, int pktsize){
	/*
	1) extract the udp packet.
	2) get the flow key: ip src, ip dst, udp src, udp dst. 
	(actually reversed, cause we see messages 
	that the server are sending back to the client)
	3) read the table file. 
	4) find the flow key in the table.
	5) look at the permission id for the flow.
	6) compare with the tag in the packet.
	7) if the tag is right, add a higher priority rule to allow the flow.
	8) if the tag is wrong, add a rule to drop packets from that connection, 
	and print a message. (probably will )
	*/
	// printf("processing a packet inside silverline module.\n");
	struct sniff_ip *ip;
	struct sniff_udp *udp;
    int size_ip;
    int size_udp;

    ip = (struct sniff_ip*)(ippkt);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return 1;
    }
    // printf("got ip header.\n");
    if (ip->ip_p == 17){
	    udp = (struct sniff_udp*)(ippkt + size_ip);
	    // printf("got udp header.\n");
	    // print_packet(ip, udp);
	    // build a flow entry. 
	    // Permission doesn't matter because it just checks the 
	    // flow key, so just use 0.
	    struct FlowEntry* newFlow = buildFlowEntry(ip, udp, 0);
		// check to see if the flow entry is there.
		// printf("looking up flow permissions...\n");
		struct FlowEntry* retFlow = getFlowEntry(newFlow);
		// Get the entry at all costs.
		// printf("getting flow entry.\n");
		while (retFlow == NULL){
			// printf("checking for flow entry...\n");
			//newFlow = buildFlowEntry(ip, udp, 0);
			retFlow = getFlowEntry(newFlow);
			usleep(1);
		}
		if (retFlow != NULL){
			// printf("\tfound entry:\n");
			// printFlowEntry(retFlow);
			// read the tag on the packet. 
			uint32_t packetTag = (uint32_t) (ip->ip_tos >>2);
			// printf("\ttag on packet: %i\n",packetTag);
			if (packetTag == retFlow->permission){ 
				// Add a new rule if you haven't already.
				if (retFlow->added == 0){
					current_time = getMsTime();
					if ((current_time-last_time)>10){
						printf("adding another flow rule.\n");
					addIpDscpFlow(retFlow->key.ip_src, retFlow->key.ip_dst,
						retFlow->key.uh_sport, retFlow->key.uh_dport,
						htonl(packetTag));
					}
					last_time=getMsTime();
					retFlow->added = 1;
				}
				return 1;
			}
			else{
				// printf("\tINVALID PERMISSION!!\n");
				return 0;
			}
		}
		else{
			// printf("\tFLOW ENTRY DOES NOT EXIST\n");
			return 0;
		}

	}
    return 1;
}

// Nothing to do for startup.
int module_startup(){
	printf("runnning data path start up function for silverline module.\n");
	last_time = 0;
	current_time = 0;
	return 1;
}

#define OFXHEADERLEN 12
struct ofxDpHeader {
    uint32_t len;
    uint32_t moduleId;
    uint32_t messageType;
};

int handle_message(struct ofxDpHeader * msgHeader, unsigned char* msg){
	struct NewPermissionRequest * newPermission;
	newPermission = (struct NewPermissionRequest *) msg;
	// printNewPermissionRequest(newPermission);
	struct FlowEntry * newFlow = buildFlowEntryFromPermission(newPermission);
	// printFlowEntry(newFlow);
	int retval = addFlowEntry(newFlow);
	if (retval>0){
		retval=-1;
		// printf("\tadded flow entry.\n");
	}
	else{
		struct FlowEntry * existingFlow = getFlowEntry(newFlow);
		// printf("\tflow entry already exists. Changing permission: %i -> %i\n",
		// 	existingFlow->permission, newFlow->permission);	
		existingFlow->permission = newFlow->permission;
	} 
	permissionCt += 1;
	if (permissionCt % 100 == 0) printf("%i permissions added.\n",permissionCt);

	return 1;
}

void error(char *msg)
{
    perror(msg);
    exit(1);
}