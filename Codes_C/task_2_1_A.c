#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>


/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4,     //IP header length
                     iph_ver:4;     //IP version
  unsigned char      iph_tos;       //Type of service
  unsigned short int iph_len;       //IP Packet length (data + header)
  unsigned short int iph_ident;     //Identification
  unsigned short int iph_flag:3,    //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl;       //Time to Live
  unsigned char      iph_protocol;  //Protocol type
  unsigned short int iph_chksum;    //IP datagram checksum
  struct  in_addr    iph_sourceip;  //Source IP address 
  struct  in_addr    iph_destip;    //Destination IP address 
};

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

static int num_of_packet = 0;
// Get captured packet
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
   
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800) {
            // Fill in the IP header
            struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
            // Define the size of IP header
            int ipHeader_lenght = ip->iph_ihl * 4;
            // Fill in the ICMP header
            struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct ethheader) + ipHeader_lenght);
            // Define the size of ICMP header
            int icmpHeader_lenght =  sizeof(struct ethhdr) + ipHeader_lenght + sizeof icmph;
            // Fill in the TCP header
            struct tcphdr *tcph = (struct tcphdr*)(packet + ipHeader_lenght + sizeof(struct ethhdr));
            // if the protocol of the IP Header is ICMP
             if( ip->iph_protocol = IPPROTO_ICMP ) {

                printf("  >> PROTOCOL: ICMP\n");
                printf("  >> PACKET #%d\n", num_of_packet);
                num_of_packet++;
                printf("  >> SRC_IP: %s\n", inet_ntoa(ip->iph_sourceip));  
                printf("  >> DST_IP: %s\n", inet_ntoa(ip->iph_destip));
                printf("DST_PORT %u ",ntohs(tcph->dest));
                printf("\n");
                return;
                }
            }
            printf("\n");
    }

int main() {

  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip proto icmp";
  bpf_u_int32 net;  // =0

  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("enp0s3", BUFSIZ, 0, 1000, errbuf);
  if (handle == NULL) {
        printf("Error: cannot open the session !\n");
  } 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             
          
  // Step 3: Capture packets
  printf(" *************** PACKET SNIFFING ****************\n ");
  pcap_loop(handle, -1, got_packet, NULL);                
  pcap_close(handle);   //Close the handle 
  return 0;

}

