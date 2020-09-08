/*
My own spoofing program written in C
Austin Peterson
UIN: 926006358
*/


#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h> 
#include <netinet/ip_icmp.h>
#include <stdio.h>


/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

u_short checkSum(char *addr, int len);

//Ethernet Header
struct eth_header {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};
//IP Header
// struct ip_header {
//  unsigned char      iph_ihl:5, iph_ver:4;
//  unsigned char      iph_tos;
//  unsigned short int iph_len;
//  unsigned short int iph_id;
//  unsigned char      iph_flag;
//  unsigned short int iph_offset;
//  unsigned char      iph_ttl;
//  unsigned char      iph_protocol;
//  unsigned short int iph_chksum;
//  unsigned int       iph_sourceip;
//  unsigned int       iph_destip;
// };
// struct ip {
// #if BYTE_ORDER == LITTLE_ENDIAN 
//     u_char  ip_hl:4,        /* header length */
//             ip_v:4;         /* version */
// #endif
// #if BYTE_ORDER == BIG_ENDIAN 
//     u_char  ip_v:4,         /* version */
//         ip_hl:4;        /* header length */
// #endif
//     u_char  ip_tos;         /* type of service */
//     short   ip_len;         /* total length */
//     u_short ip_id;           identification 
//     short   ip_off;         /* fragment offset field */
// #define IP_DF 0x4000            /* dont fragment flag */
// #define IP_MF 0x2000            /* more fragments flag */
//     u_char  ip_ttl;         /* time to live */
//     u_char  ip_p;           /* protocol */
//     u_short ip_sum;         /* checksum */
//     struct  in_addr ip_src,ip_dst;  /* source and dest address */
// };

#define BUFFER_SIZE 1024


struct eth_header* buildEthernetHeader(char* source_mac, char* dest_mac){
        struct eth_header* eth;
        eth = (struct eth_header*)malloc(SIZE_ETHERNET);

        
        strcpy(eth->ether_shost, source_mac);
        strcpy(eth->ether_dhost, dest_mac);
        eth->ether_type = 'ARP';        //pretty sure

        return eth;
}

struct ip* buildIPHeader(char* source_addr, char* dest_addr){
        struct ip* ipHeader;
        int size = sizeof(struct icmphdr) + sizeof(struct ip)+1;

        ipHeader = (struct ip_header*)malloc(sizeof(struct ip));
        // ip->ip_vhl = 4;
        // ip->ip_tos=0;                 /* type of service */
        // ip->ip_len = sizeof(struct ip_header);                /* total length */
        // ip->ip_id = rand();                 /* identification */
        // ip->ip_off = 0;                  fragment offset field 
        // ip->ip_ttl = rand();                /* time to live */
        // ip->ip_p = IPPROTO_ICMP;                 /* protocol */
        // inet_aton(source_addr, &ip->ip_src);
        // inet_aton(dest_addr, &ip->ip_dst);
        // ip->version = 4;
        ipHeader->ip_tos = 0;
        ipHeader->ip_len = htons(size);
        ipHeader->ip_id = rand();
        ipHeader->ip_off = 0;
        ipHeader->ip_ttl = 64;
        ipHeader->ip_p = IPPROTO_ICMP;
        // ipHeader->ip_src = inet_addr(source_addr);
        // ipHeader->ip_dst = inet_addr(dest_addr);
        inet_aton(source_addr, &ipHeader->ip_src);
        inet_aton(dest_addr, &ipHeader->ip_dst);
        ipHeader->ip_sum = checkSum((char*) ipHeader, ipHeader->ip_len);

        return ipHeader;
}


struct icmp_header* buildICMPHeader(){
        struct icmphdr* icmp;

        icmp = (struct icmphdr*)malloc(sizeof(struct icmphdr));

        icmp->type = ICMP_ECHO;


        return icmp;
} 

//function I found online to calculate checksum
u_short checkSum(char *addr, int len){
      long sum = 0;  /* assume 32 bit long, 16 bit short */

       while(len > 1){
         int temp = *((unsigned short*)addr);
         sum += temp++;
         if(sum & 0x80000000)   /* if high order bit set, fold */
           sum = (sum & 0xFFFF) + (sum >> 16);
         len -= 2;
       }

       if(len)       /* take care of left over byte */
         sum += (unsigned short) *(unsigned char *)addr;

       while(sum>>16)
         sum = (sum & 0xFFFF) + (sum >> 16);

       return ~sum;
}

int main(){

int sd;
struct sockaddr_in sin;
char buffer[BUFFER_SIZE]; //You can change the buffer size
const int on =1;

/*Create a raw socket with IP protocol. The IPProto_Raw parameter tells the system that the IP header is already included. This prevents the OS from adding another IP header */
sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
if(sd<0){
	perror("socket() error");
	exit(-1);
}

/* this data structure is needed when sending the packets using sockets. Normally, we need to fill out several fields, but for raw sockets we only need to fill out this one field */

sin.sin_family = AF_INET;

//Here you can construct the IP packet using buffer[]
char* source_mac = "08:00:27:41:75:67"; 
char* dest_mac = "08:00:27:15:d5:0b"; 
char* source_string = "10.0.2.5";
char* dest_string = "10.0.2.4";





struct eth_header* eth_hdr = buildEthernetHeader(source_mac, dest_mac);
struct ip* ip_hdr = buildIPHeader(source_string, dest_string);
struct icmphdr* icmp_hdr = buildICMPHeader();

// memcpy(buffer, eth_hdr, SIZE_ETHERNET);
// memcpy(buffer + SIZE_ETHERNET, ip_hdr, sizeof(struct ip_header));
// memcpy(buffer+SIZE_ETHERNET+sizeof(struct ip_header), icmp_hdr, sizeof(struct icmphdr));

memcpy(buffer, ip_hdr, sizeof(struct ip));
memcpy(buffer + sizeof(struct ip), icmp_hdr, sizeof(struct icmphdr));

if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("setsockopt");
    exit(1);
  }
//fill in the data part if needed

//Note: you shoudl pat attention to the network/host byte order

/*send out the ip packet. ip_len is thee actual size of the packet */

if(sendto(sd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&sin,sizeof(sin))<0){
	perror("sendto() error");
	exit(-1);
}
else{
        printf("Packet Sent");
}

return 0;
}


