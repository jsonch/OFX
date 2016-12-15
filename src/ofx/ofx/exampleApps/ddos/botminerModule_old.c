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


int handle_packet(unsigned char * ethpkt, unsigned char * ippkt, int pktsize){
	// printf("handling packet in botminer processor.\n");
	// Add a flood rule for the flow..
	// That's really all the module _needs_ to do at this level.
	// The python module can do all the polling for flow stats.
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
    if (ip->ip_p == 17){
	    udp = (struct sniff_udp*)(ippkt + size_ip);
		char src[32];
		char dst[32];
		char flow[256];
		strcpy(src,inet_ntoa(ip->ip_src));
		strcpy(dst,inet_ntoa(ip->ip_dst));
        addUDPCountingFlow(ip->ip_src, ip->ip_dst, udp->uh_sport, udp->uh_dport);
		// sprintf(flow, "sudo ovs-ofctl add-flow s1 \"dl_type=0x0800, nw_proto=17, nw_src=%s, nw_dst=%s,udp_src=%i, udp_dst=%i, actions=FLOOD\" &",
		// 	src, dst, ntohs(udp->uh_sport), ntohs(udp->uh_dport));
		// printf("\tadding flow: \n");
		// printf("\t%s",flow);
		// system(flow);
	}

	return 1;
}
int module_startup(){
	printf("runnning start up function for botminer module.\n");
	return 1;
}
