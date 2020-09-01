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
//#include <ip_icmp.h>


//IP Header
struct ip_header {
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
        int ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


// TCP header 

int main(){

int sd;
struct sockaddr_in sin;
char buffer[1024]; //You can change the buffer size

/*Create a raw socket with IP protocol. The IPProto_Raw parameter tells the system that the IP header is already included. This prevents the OS from adding another IP header */

sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
if(sd<0){
	perror("socket() error");
	exit(-1);
}

/* this data structure is needed when sending the packets using sockets. Normally, we need to fill out several fields, but for raw sockets we only need to fill out this one field */

sin.sin_family = AF_INET;


//Here you can construct the IP packet using buffer[]


    
struct ip_header* ip = (struct ip_header*)buffer;

struct icmp* icmp = (struct icmp*)buffer + sizeof(ip);

ip->ip_len = 420;
ip->ip_p = IPPROTO_ICMP;

icmp->icmp_type = ICMP_ECHO;
icmp->icmp_code = 0;
icmp->icmp_id = 123;
icmp->icmp_seq = 0;

char* source_string = "10.0.2.5";
char* dest_string = "10.0.2.4";
//set source and destination ip
ip->ip_src = inet_addr(source_string);
ip->ip_dst = inet_addr(dest_string);


//fill in the data part if needed

//Note: you shoudl pat attention to the network/host byte order

/*send out the ip packet. ip_len is thee actual size of the packet */
size_t ip_len = sizeof(buffer);
if(sendto(sd, buffer, ip_len, 0, (struct sockaddr*) &sin,sizeof(sin))<0){
	perror("sendto() error");
	exit(-1);
}

return 0;
}

