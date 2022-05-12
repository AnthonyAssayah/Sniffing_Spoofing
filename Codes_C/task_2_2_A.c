#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>


#define PACKET_LEN 1500

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

void send_raw_ip_packet(struct ipheader* ip) {
	struct sockaddr_in dest_info;
	int enable = 1;
	//Step1: Create a raw network socket
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	//Step2: Set Socket option
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	//Step3: Provide destination information
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	//Step4: Send the packet out
	printf("********* SENDING SPOOFED PACKET **********\n");
	if (sendto(sock, ip, ntohs(ip->iph_len),0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
	printf("%sError: failed sending message !","");
    	}
    	else{
    	
    	printf("\t>> IP SOURCE: %s\n", inet_ntoa(ip->iph_sourceip));
    	printf("\t>> IP DEST: %s\n", inet_ntoa(ip->iph_destip));
    	printf("\n");
	}
	close(sock);
}

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   return (unsigned short)(~sum);
}

int main() {

	char buffer[PACKET_LEN]; 
	memset(buffer, 0, PACKET_LEN);
	
	// Fill in the ICMP header
	struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));

	//ICMP type 8 for request and 0 for replay
	icmp->icmp_type = 8;

	// Calculate checksum
	icmp->icmp_chksum = 0;
	icmp-> icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));

	//Fill in the IP header
	struct ipheader *ip = (struct ipheader *) buffer;
	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_tos = 16;
	ip->iph_ttl = 128;
	ip->iph_sourceip.s_addr = inet_addr("8.8.8.8");
	ip->iph_destip.s_addr = inet_addr("10.0.2.6");
	ip->iph_protocol = IPPROTO_ICMP;
	ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

   send_raw_ip_packet (ip);

   return 0;
}
