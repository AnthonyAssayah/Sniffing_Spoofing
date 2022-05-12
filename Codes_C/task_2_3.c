#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <string.h>
#include <errno.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport;           /* source port */
  u_int16_t udp_dport;           /* destination port */
  u_int16_t udp_ulen;            /* udp length */
  u_int16_t udp_sum;             /* udp checksum */
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

/* Psuedo TCP header */
struct pseudo_tcp
{
        unsigned saddr, daddr;
        unsigned char mbz;
        unsigned char ptcl;
        unsigned short tcpl;
        struct tcpheader tcp;
        char payload[1500];
};

#define PACKET_LEN 1500

/*************************************************************
  Given an IP packet, send it out using a raw socket.
**************************************************************/
void send_raw_ip_packet(struct ipheader* ip) {
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: create a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: set socket option
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed info about destination
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: send the packet out
       printf("************ SENDING SPOOFED PACKET **********\n\n");

    if (sendto(sock, ip, ntohs(ip->iph_len), 0,(struct sockaddr *)&dest_info, sizeof(dest_info)) < 0){

    	fprintf(stderr, "sendto() failed with error: %d", errno);

    	}

    	else{


    	printf("\t>> IP SRC:%s\n", inet_ntoa(ip->iph_sourceip));

    	printf("\t>> IP DST:%s\n", inet_ntoa(ip->iph_destip));

    	printf("\n");

	}
    
}

/*******************************
  Spoof an ICMP echo request
********************************/
void send_reply_packet(struct ipheader * ip) {
  
  char buffer[PACKET_LEN];
  int ip_header_len = ip->iph_ihl * 4;

  //Make copy from the sniffed packet
  memset((char *)buffer, 0, PACKET_LEN);
  memcpy((char *)buffer, ip, ntohs(ip->iph_len));
  struct ipheader* new_ip = (struct ipheader*) buffer;
  struct icmpheader* new_icmp = (struct icmpheader*) (buffer + sizeof(ip_header_len));

  //Swap source and destination for echo reply
  new_ip->iph_sourceip = ip->iph_destip;
  new_ip->iph_destip   = ip->iph_sourceip;
  new_ip->iph_ttl = 128;

  //ICMP echo reply type is 0
  new_icmp->icmp_type = 0;

  send_raw_ip_packet(new_ip);
}

void got_packet(u_char *args, const struct pcap_pkthdr * header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader*) packet;

  if(ntohs(eth->ether_type) == 0x0800) { // 0x0800 = IP TYPE
    struct ipheader *ip = (struct ipheader*) (packet + sizeof(struct ethheader));
    printf("************** SNIFFING PACKET ***************\n\n");
    printf("\t>> IP SRC:%s\n", inet_ntoa(ip->iph_sourceip));   
    printf("\t>> IP DST:%s\n", inet_ntoa(ip->iph_destip));   

  // Determine protocol
  switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("\t>> PROTOCOL: TCP\n\n");
            return;
        case IPPROTO_UDP:
            printf("\t>> PROTOCOL: UDP\n\n");
            return;
        case IPPROTO_ICMP:
            printf("\t>> PROTOCOL: ICMP\n\n");
        	    send_reply_packet(ip);
            return;
        default:
            printf("\t>> OTHERS PROTOCOLS\n");
            return;
    }

  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip proto icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);
  return 0;  
}
