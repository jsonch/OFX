#include <stdio.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// the magical hash table..
#include "uthash.h"

#define ETHER_ADDR_LEN  6
#define SIZE_ETHERNET 14
/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

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


/* TCP header */
typedef u_int tcp_seq;
 
struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
            #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};


// Key for entries in the completed connection table. 
struct complete_connection_key{
    u_short th_sport;        
    u_short th_dport;
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
    };

struct complete_connection_entry{
    struct complete_connection_key key;
    UT_hash_handle hh;
};

struct complete_connection_entry* cc_hashtable;
int cc_total_count = 0;

// Build a new entry into the syn ack table.
struct complete_connection_entry* build_cc_entry(struct sniff_ip* ip, struct sniff_tcp* tcp){
    // Build the new hash table entry.
    struct complete_connection_entry * newEntry = calloc(1, sizeof(struct complete_connection_entry));
    newEntry->key.th_sport = tcp->th_sport;
    newEntry->key.th_dport = tcp->th_dport;
    newEntry->key.ip_src = ip->ip_src;
    newEntry->key.ip_dst = ip->ip_dst;
    return newEntry;
}

// Build the entry that you use to check if an ack packet matches an existing entry.
struct complete_connection_entry* build_reverse_cc_entry(struct sniff_ip* ip, struct sniff_tcp* tcp){
    struct complete_connection_entry * newEntry = calloc(1, sizeof(struct complete_connection_entry));

    newEntry->key.th_dport = tcp->th_sport;
    newEntry->key.th_sport = tcp->th_dport;
    newEntry->key.ip_dst = ip->ip_src;
    newEntry->key.ip_src = ip->ip_dst;
    return newEntry;
}

int add_cc_table_hash(struct complete_connection_entry* newEntry)
{
    // Check if something with this syn / ack already exists in the hash table. If so, don't add it.
    struct complete_connection_entry * existingEntry; 
    HASH_FIND(hh, cc_hashtable, &newEntry->key, sizeof(struct complete_connection_key), existingEntry);
    if (existingEntry){
        return -1;
    }        
    HASH_ADD(hh, cc_hashtable, key, sizeof(struct complete_connection_key), newEntry);
    cc_total_count += 1;

    HASH_FIND(hh, cc_hashtable, &newEntry->key, sizeof(struct complete_connection_key), existingEntry);
    return 1;
}

// Look up an entry in the hash table. If it doesn't exist, return -1. If it does, return the entry.
struct complete_connection_entry* get_cc_table_hash(struct complete_connection_entry* queryEntry)
{
    struct complete_connection_entry * existingEntry;
    HASH_FIND(hh, cc_hashtable, &queryEntry->key, sizeof(struct complete_connection_key), existingEntry);
    if (!existingEntry){
        return -1;
    }
        return existingEntry;
}


int print_cc_key(struct complete_connection_key * key){
    char src[32];
    char dst[32];
    strcpy(src,inet_ntoa(key->ip_src));
    strcpy(dst,inet_ntoa(key->ip_dst));                                                             
    printf("\tsrc:%s\tdst:%s\tsport:%hu\tdport:%hu\n",src,dst,key->th_sport,key->th_dport);
    return 1;
}

// Key for entries in the syn ack hash table.
struct syn_ack_key {
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */        
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct syn_ack_entry {
    struct syn_ack_key key; // hash index.
    int matched; //flag to indicate whether the connection is fully established yet.
    UT_hash_handle hh; // handle so it can be hashed..
};

struct syn_ack_entry* sa_hashtable;
int total_count = 0;

// Build a new entry into the syn ack table.
struct syn_ack_entry* build_syn_ack_entry(struct sniff_ip* ip, struct sniff_tcp* tcp){
    // Build the new hash table entry.
    struct syn_ack_entry * newEntry = calloc(1, sizeof(struct syn_ack_entry));
    newEntry->key.th_seq = ntohl(tcp->th_seq);
    newEntry->key.th_ack = ntohl(tcp->th_ack);
    newEntry->key.ip_src = ip->ip_src;
    newEntry->key.ip_dst = ip->ip_dst;
    newEntry->matched = 0;
    return newEntry;
}

// Build the entry that you use to check if an ack packet matches an existing entry.
struct syn_ack_entry* build_reverse_syn_ack_entry(struct sniff_ip* ip, struct sniff_tcp* tcp){
    struct syn_ack_entry * newEntry = calloc(1, sizeof(struct syn_ack_entry));

    tcp_seq ack_check = ntohl(tcp->th_seq);
    tcp_seq seq_check = ntohl(tcp->th_ack);
    seq_check --;
    newEntry->key.th_seq = seq_check;
    newEntry->key.th_ack = ack_check;
    newEntry->key.ip_src = ip->ip_dst;
    newEntry->key.ip_dst = ip->ip_src;
    return newEntry;
}


int print_key(struct syn_ack_key * key){
    char src[32];
    char dst[32];
    strcpy(src,inet_ntoa(key->ip_src));
    strcpy(dst,inet_ntoa(key->ip_dst));                                                             
    printf("KEY:\tseq:%u\n\tack:%u\n\tsrc:%s\n\tdst:%s\n",key->th_seq,key->th_ack,src,dst);
}


int add_syn_ack_table_hash(struct syn_ack_entry* newEntry)
{
    // Check if something with this syn / ack already exists in the hash table. If so, don't add it.
    struct syn_ack_entry * existingEntry; 
    HASH_FIND(hh, sa_hashtable, &newEntry->key, sizeof(struct syn_ack_key), existingEntry);
    if (existingEntry){
        return -1;
    }    
    HASH_ADD(hh, sa_hashtable, key, sizeof(struct syn_ack_key), newEntry);
    // You can do evictions here too: delete all values smaller than total_count - x, then update a first_index parameter.
    total_count += 1;
    return 1;
}


// Look up an entry in the hash table. If it doesn't exist, return -1. If it does, return the entry.
struct syn_ack_entry* get_syn_ack_table_hash(struct syn_ack_entry* queryEntry)
{
    struct syn_ack_entry * existingEntry;
    HASH_FIND(hh, sa_hashtable, &queryEntry->key, sizeof(struct syn_ack_key), existingEntry);
    if (!existingEntry){
        return -1;
    }
        return existingEntry;
}

int print_packet(struct sniff_ethernet* ethernet, struct sniff_ip* ip, struct sniff_tcp* tcp, int packetsize)
{
    printf("--------------------------------\n");
    printf("\tsrc: %02X:%02X:%02X:%02X:%02X:%02X ", ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
    printf("\tdst: %02X:%02X:%02X:%02X:%02X:%02X\n", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
    printf("\toriginal packet size:%i\n",packetsize);
    /* print source and destination IP addresses */
    printf("\tFrom: %s\n", inet_ntoa(ip->ip_src));
    printf("\tTo: %s\n", inet_ntoa(ip->ip_dst));
    printf("\tSrc port: %d\n", ntohs(tcp->th_sport));
    printf("\tDst port: %d\n", ntohs(tcp->th_dport));
    if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) {
        printf("\tSYN + ACK packet.\n");        
    }
    else if (tcp->th_flags & TH_SYN){
        printf("\tSYN packet.\n");
    }   
    else if  ((tcp->th_flags & TH_ACK) && !(tcp->th_flags & TH_RST)){
    printf("\tACK packet (NO RST)\n");
    }   
    printf("\tSEQ: %u",ntohl(tcp->th_seq));
    printf("\tACK: %u\n",ntohl(tcp->th_ack));
    printf("--------------------------------\n");
}


/************************************************************
 * The main packet handler.                                 *
 * The higher level extension module must install flows to  *
 * route based on all tag values returned by this function. *
 ************************************************************/
int handle_packet(unsigned char * ethpkt, unsigned char * ippkt, int pktsize)
{    

    /* declare pointers to packet headers */
    struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    struct sniff_ip *ip;              /* The IP header */
    struct sniff_tcp *tcp;            /* The TCP header */
    int size_ip;
    int size_tcp;
    // Parse headers and payload sizes.
    ethernet = (struct sniff_ethernet*)(ethpkt);
    ip = (struct sniff_ip*)(ippkt);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        printf("\tMODULE INSTRUCTION: DROP.\n");
        return 0;
    }
    tcp = (struct sniff_tcp*)(ippkt + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        printf("\tMODULE INSTRUCTION: DROP.\n");
        return 0;
    }

    // main logic: handling of syn, syn + ack, and regular acks.

    // Case SYN + ACK: store the half-initiated connection information, then flood.
    if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) {
        // If this is a repeat of a syn+ack we sent out, drop it.
        struct syn_ack_entry *checkEntry = build_syn_ack_entry(ip, tcp);
        if (get_syn_ack_table_hash(checkEntry)> -1){
            free(checkEntry);
            // printf("\tMODULE INSTRUCTION: INVALID SYN+ACK, DROP.\n");
            return 0;
        }
        add_syn_ack_table_hash(checkEntry);
        // printf("\tMODULE INSTRUCTION: SYN + ACK, FLOOD.\n");
        return 1;
    }
    // Case SYN: Just flood the packet.
    else if (tcp->th_flags & TH_SYN){
        // printf("\tMODULE INSTRUCTION: SYN PACKET, FLOOD.\n");
        return 1;
    }
    // Case ACK: if the packet corresponds to a half open a connection, 
    //           forward it to the controller. If not, drop. 
    else if  ((tcp->th_flags & TH_ACK) && !(tcp->th_flags & TH_RST)) {
        // Check if its a completed connection.
        struct complete_connection_entry *check_cc_entry = build_cc_entry(ip, tcp);
        if (get_cc_table_hash(check_cc_entry) != -1){
            free(check_cc_entry);
            // printf("\tMODULE INSTRUCTION: EXISTING CONNECTION, FORWARD TO CONTROLLER.\n");
            addTCPFloodFlow(ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport);
            addTCPFloodFlow(ip->ip_dst, ip->ip_src, tcp->th_dport, tcp->th_sport);
            sendPacketUp(ethpkt, pktsize);
            return 0;            
        }
        free(check_cc_entry);

        // check if it completes a half opened connection.
        struct syn_ack_entry *checkEntry = build_reverse_syn_ack_entry(ip, tcp);
        if (get_syn_ack_table_hash(checkEntry) != -1) {
            struct complete_connection_entry *cc_entry = build_cc_entry(ip, tcp);
            add_cc_table_hash(cc_entry);
            struct complete_connection_entry *reverse_cc_entry = build_reverse_cc_entry(ip, tcp);
            add_cc_table_hash(reverse_cc_entry);
            // printf("\tMODULE INSTRUCTION: CONNECTION COMPLETED, FORWARD TO CONTROLLER.\n");
            addTCPFloodFlow(ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport);
            addTCPFloodFlow(ip->ip_dst, ip->ip_src, tcp->th_dport, tcp->th_sport);
            sendPacketUp(ethpkt, pktsize);
            free(checkEntry);
            return 1;
        }
        // If its not an ack that matches a syn+ack in the table, drop it.
        else {
            printf("\tMODULE INSTRUCTION: NO CONNECTION MATCH, DROP.\n");
            free(checkEntry);
            return 1;
        }
    }
}

int module_startup(){
    printf("runnning start up function for avantguard packet processor.\n");
    return 1;
}
