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

MODULEID=0x41;


// switch <--> data plane messages.
GETFLOWS = 0x11;
FLOWSTATS = 0x22;


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
void* statsThread(void *);
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
	uint32_t byteCt; // how many packets have we seen?
	UT_hash_handle hh;
};

// The flow hash table.
struct FlowEntry* flow_HT;
int flowCt = 0;

int entryAttempts = 0;
int flowsAddedToAsic = 0;

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

// Build a flow entry.
struct FlowEntry* buildFlowEntry(struct sniff_ip* ip, struct sniff_udp* udp){
	struct FlowEntry* newFlow = calloc(1, sizeof(struct FlowEntry));
	newFlow->key.ip_src = ip->ip_src;
	newFlow->key.ip_dst = ip->ip_dst;
	newFlow->key.uh_sport = udp->uh_sport;
	newFlow->key.uh_dport = udp->uh_dport;
	newFlow->byteCt = 0;
	newFlow->added = 0;
	return newFlow;
}


// Print out a flow entry.
int printFlowEntry(struct FlowEntry * flow){
	char src[32];
    char dst[32];
    strcpy(src,inet_ntoa(flow->key.ip_src));
    strcpy(dst,inet_ntoa(flow->key.ip_dst));  
	printf("\tFlow: %s (%i) --> %s (%i): Packet ct %i \n", 
		src, ntohs(flow->key.uh_sport), 
		dst, ntohs(flow->key.uh_dport), 
		flow->byteCt);
}


// functions that the OFX agent calls.
int handle_packet(unsigned char * ethpkt, unsigned char * ippkt, int pktsize){
	/*
	1) extract the udp packet.
	2) get the flow key: ip src, ip dst, udp src, udp dst. 
	3) update flow stats table, add a new entry if it doesnt exist.
	4) add a rule, if you haven't already.
	*/
	struct sniff_ip *ip;
	struct sniff_udp *udp;
    int size_ip;
    int size_udp;
    ip = (struct sniff_ip*)(ippkt);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return 0;
    }
    // What do we want to tap? IP packets, or udp packets?
    // printf("got ip header.\n");
    if (ip->ip_p == 17){
	    udp = (struct sniff_udp*)(ippkt + size_ip);
	    // printf("got udp header.\n");
	    // print_packet(ip, udp);
	    // build a flow entry. 
	    struct FlowEntry* newFlow = buildFlowEntry(ip, udp);
		// check to see if the flow entry is there.
		// printf("looking up flow permissions...\n");
		struct FlowEntry* retFlow = getFlowEntry(newFlow);
		struct FlowEntry* flow;
		// If its not there, add it.
		if (retFlow == NULL){
			addFlowEntry(newFlow);
			flow = newFlow;
		}
		// If it is there, use the existing flow.
		else{
			flow = retFlow;
		}
		// Flow processing:
		// 1) update the packet counter.
		flow->byteCt += 1;
		// 2) if you've never tried to add a rule, do so now.
		if (flow->added == 0){
			// print_packet(ip, udp);
			entryAttempts +=1;
			current_time = getMsTime();
			// printf("LAST TICK: %f\n",last_time);
			// printf("CURR TICK: %f\n",current_time);

			if ((current_time-last_time)>10){
				addUDPCountingFlow(flow->key.ip_src, flow->key.ip_dst,
				flow->key.uh_sport, flow->key.uh_dport);
				flowsAddedToAsic +=1;
				last_time=getMsTime();
			}			
			flow->added = 1; // stop trying to add the flow.
		}
	}
	// Return 0. Never send the packet back. This is a tap application.
	return 0;
}

int module_startup(){
	last_time = 0;
	current_time = 0;
	printf("runnning data path start up function for botminer module.\n");
	// 1) start a thread that sends up statistics updates.
	pthread_t pth; // thread identifier.
	// start the thread. First, you should initialize whatever 
	// data structures the thread will need. 
	pthread_create(&pth, NULL, statsThread, "starting stats thread...");	
	return 1;
}

int handle_message(struct ofxDpHeader * msgHeader, unsigned char* msg){
	return 1;
}


// Example of iterating through a hash table:
// Just open a file, then iterate through and write each struct to the file.
// You can open and parse the hash table later.
// void print_users() {
//     struct my_struct *s;

//     for(s=users; s != NULL; s=s->hh.next) {
//         printf("user id %d: name %s\n", s->id, s->name);
//     }
// }

struct FlowEntryNoHash{
	struct FlowKey key;
	uint32_t permission;
	uint32_t added; // Has the rule been added?
	uint32_t byteCt; // how many packets have we seen?
};
// Entry size: 12 + 4 + 4 + 4 = 24.

void* statsThread(void *arg){

	struct FlowEntryNoHash* flowArray = calloc(20000, sizeof(struct FlowEntryNoHash));

	while(1){
		// printf("gathering statistics about flows.\n");
		struct FlowEntry* flow;
		int idx = 0;
		// Load up the array of flow entries.
		for (flow = flow_HT; flow != NULL; flow=flow->hh.next){
			// Don't copy the hash table handler.
			memcpy(&flowArray[idx], flow, (sizeof(struct FlowEntryNoHash)));
			// Make sure everything is in network byte order. 
			// The packet info already is, we never changed it.
			flowArray[idx].permission = htonl(flowArray[idx].permission);
			flowArray[idx].added = htonl(flowArray[idx].added);
			flowArray[idx].byteCt = htonl(flowArray[idx].byteCt);
			idx +=1;
		}
		// printf("copied %i flow entries.\n",idx);		
		// printf("%i flow entries added to asic. (out of %i attempts)\n",flowsAddedToAsic, entryAttempts);		
		sendTypedMsgUp((unsigned char *)flowArray, sizeof(struct FlowEntryNoHash)*(idx),MODULEID, FLOWSTATS);
		sleep(1);
	}

}

