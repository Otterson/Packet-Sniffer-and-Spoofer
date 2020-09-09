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

/*
In this task, you will combine the sniffing and spoofing techniques to implement the following
sniff-and- then-spoof program. You need two VMs on the same LAN. From VM A, you ​ ping ​ anIP X. This will
CSCE 465 Computer and Network Security ​ 4
generate an ICMP echo request packet. If X is alive, the ​ ping ​ program will receive an echo
reply, and print out the response. Your sniff-and-then-spoof program runs on VM B, which
monitors the LAN through packet sniffing. Whenever it sees an ICMP echo request, regardless of
what the target IP address is, your program should immediately send out an echo reply using the
packet spoofing technique. Therefore, regard- less of whether machine X is alive or not, the
ping ​ program will always receive a reply, indicating that X is alive. You need to write such a
program, and include screendumps in your report to show that your program works. Please also
attach the code (with adequate amount of comments) in your report./*
*/
#define SIZE_ETHERNET 14

#define SNAP_LEN 1518
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

#define BUFFER_SIZE 100


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
        //ipHeader->ip_sum = checkSum((char*) ipHeader, ipHeader->ip_len);

        return ipHeader;
}

struct icmphdr* buildICMPHeader(){
        struct icmphdr* icmp = (struct icmphdr*)malloc(sizeof(struct icmphdr));
        icmp->type = ICMP_ECHOREPLY;
        icmp->code = 0;
        icmp->checksum = 0;

       // icmp->checksum = in_cksum(icmp, sizeof(struct icmphdr));

        return icmp;
} 

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ip *ip; /* The IP header */

    int size_ip;

    printf("ICMP Packet Received\n");
    const int on =1;


    /* define/compute ip header offset */
    ip = (struct ip *)(packet + SIZE_ETHERNET);
    size_ip = ip->ip_hl * 4;
    if (size_ip < 20)
    {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    //Create and send spoof packet
    int sd;
    struct sockaddr_in sin;
    char buffer[100];

    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0)
    {
        perror("socket() error");
        exit(-1);
    }

    sin.sin_family = AF_INET;

    struct ip* ipHeader = buildIPHeader(inet_ntoa(ip->ip_dst), inet_ntoa(ip->ip_src));
    ipHeader->ip_dst = ip->ip_src;
    struct icmphdr* icmpHeader = buildICMPHeader();

    memcpy(buffer, ipHeader, sizeof(struct ip));
    memcpy(buffer+sizeof(struct ip), icmpHeader, sizeof(struct icmphdr));

    size_t packet_len = sizeof(buffer);

    sin.sin_addr.s_addr = ip->ip_dst.s_addr;

if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("setsockopt");
    exit(1);
  }

    printf("Sending Spoofed Response Packet\n");
    printf("       From: %s\n", inet_ntoa(ipHeader->ip_src));
    printf("         To: %s\n\n", inet_ntoa(ipHeader->ip_dst));

    if (sendto(sd, buffer, packet_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        perror("sendto() error");
        exit(-1);
    }

    return;
}

int main()
{
    char *dev = NULL;              /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
    pcap_t *handle;                /* packet capture handle */
    const int on =1;

    char filter_exp[] = "icmp and (src host 10.0.2.4)"; /* filter expression [3] */
    struct bpf_program fp;      /* compiled filter program (expression) */
    bpf_u_int32 mask;           /* subnet mask */
    bpf_u_int32 net;            /* ip */
    int num_packets = 10;       /* number of packets to capture */

    //print_app_banner();

    /* check for capture device name on command-line */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n",
                errbuf);
        exit(EXIT_FAILURE);
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;
}