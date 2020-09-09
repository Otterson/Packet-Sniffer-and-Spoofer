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

#define BUFFER_SIZE 84

u_short checkSum(char *addr, int len);

//Ethernet Header
// struct eth_header {
//         u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
//         u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
//         u_short ether_type;                     /* IP? ARP? RARP? etc */
// }

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


// struct eth_header* buildEthernetHeader(char* source_mac, char* dest_mac){
//         struct eth_header* eth;
//         eth = (struct eth_header*)malloc(SIZE_ETHERNET);

//         strcpy(eth->ether_shost, source_mac);
//         strcpy(eth->ether_dhost, dest_mac);
//         eth->ether_type = 'IP';        //pretty sure

//         return eth;
// }

struct ip* buildIPHeader(char* source_addr, char* dest_addr){
        struct ip* ipHeader;
        int size = sizeof(struct icmphdr) + sizeof(struct ip)+1;

        ipHeader = (struct ip*)malloc(sizeof(struct ip));
        ipHeader->ip_tos = 0;
        ipHeader->ip_v = 4;
        ipHeader->ip_hl = (sizeof(struct ip))/4;
        ipHeader->ip_len = htons(size);
        ipHeader->ip_id = rand();
        ipHeader->ip_off = 0;
        ipHeader->ip_ttl = 64;
        ipHeader->ip_p = IPPROTO_ICMP;
        inet_aton(source_addr, &ipHeader->ip_src);
        inet_aton(dest_addr, &ipHeader->ip_dst);
        ipHeader->ip_sum = checkSum((char*) ipHeader, ipHeader->ip_len);
        //printf("IP header sizeof: %s\n", ipHeader->ip_hl);
        return ipHeader;
}

struct icmphdr* buildICMPHeader(){ 
        struct icmphdr* icmp = (struct icmphdr*)malloc(sizeof(struct icmphdr));
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->checksum = 0;

        icmp->checksum = checkSum((char *)&icmp, 2);
  printf("chksum: %x\n",checkSum((char *)&icmp, sizeof(icmp)));
  //icmp->checksum = htons(0x8336);
        //icmp->checksum = in_cksum((unsigned short*)icmp, sizeof(struct icmphdr));
        return icmp;
} 


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

char* source_string = "4.4.4.4";    //spoof source address
char* dest_string = "10.0.2.4";

//struct eth_header* eth_hdr = buildEthernetHeader(source_mac, dest_mac); //didnt get used
struct ip* ip_hdr = buildIPHeader(source_string, dest_string);      //build IP header
struct icmphdr* icmp_hdr = buildICMPHeader();                       //build icmp header

printf("IP header size: %d\n", sizeof(struct ip));
printf("ICMP header size: %d\n", sizeof(struct icmphdr));

// memcpy(buffer, eth_hdr, SIZE_ETHERNET);
// memcpy(buffer + SIZE_ETHERNET, ip_hdr, sizeof(struct ip));
// memcpy(buffer+SIZE_ETHERNET+sizeof(struct ip), icmp_hdr, sizeof(struct icmphdr));

memcpy(buffer, ip_hdr, sizeof(struct ip)+1);                //copy headers into packet buffer
memcpy(buffer + sizeof(struct ip), icmp_hdr, sizeof(struct icmphdr));   


sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);    //create socket
if(sd<0){
    perror("socket() error");
    exit(-1);
}
sin.sin_family = AF_INET;
sin.sin_addr.s_addr = ip_hdr->ip_dst.s_addr;                    //set socket source addr

bind(sd, (struct sockaddr*)&sin, sizeof(sin));                 
if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("setsockopt");
    exit(1);
  }

if(sendto(sd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&sin,sizeof(sin))<0){
	perror("sendto() error");                              //send packet
	exit(-1);
}
else{
        printf("Packet Sent\n");
}
return 0;
}


