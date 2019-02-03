#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

// Initialise variables to store the number of malicious packets we monitor
unsigned long xmas = 0;
unsigned long arpReply = 0;
unsigned long urlblack = 0;
int verboseOn = 0;

// Initialise mutex locks
pthread_mutex_t lockArpReply = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lockXmas = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lockBlacklist = PTHREAD_MUTEX_INITIALIZER;

// Print source and destination addresses
void printMac(struct ether_header *ethhdr)
{
  printf("* Source MAC: %02x", ethhdr->ether_shost[0]);
  int i;
  for (i = 1; i < ETH_ALEN; i++) {
    printf(":%02x", ethhdr->ether_shost[i]);
  }
  printf("\n * Destination MAC: %02x", ethhdr->ether_dhost[0]);
  for (i = 1; i < ETH_ALEN; i++) {
    printf(":%02x", ethhdr->ether_shost[i]);
  }
  printf("\n");
}

// Found a Reply, count and print it if -v
void arpReplyDetected(struct ether_header *ethhdr)
{
  pthread_mutex_lock(&lockArpReply);
  arpReply++;
  pthread_mutex_unlock(&lockArpReply);
  if (verboseOn)
  {
    printf("\n **************************************\n * ARP Response Detected\n ");
    printMac(ethhdr);
    printf(" **************************************\n");
  }
}

// Found a Xmas packet, count and print it if -v
void xmasDetected(struct ether_header *ethhdr, char* ipSource, char* ipDest, int tcpSource, int tcpDest)
{
	pthread_mutex_lock(&lockXmas);
	xmas++;
	pthread_mutex_unlock(&lockXmas);
	if (verboseOn) {
    printf("\n **************************************\n * Xmas packet Detected\n ");
    printMac(ethhdr);
    printf(" * Source IP/TCP port: %s:%d\n * Destination IP/TCP port: %s:%d\n ",ipSource, tcpSource, ipDest, tcpDest);
    printf(" **************************************\n");
	}
}

// Found a blacklisted url request, count and print it if -v
void urlDetected(struct ether_header *ethhdr, char* ipSource, char* ipDest, int tcpSource, int tcpDest)
{
	pthread_mutex_lock(&lockBlacklist);
	urlblack++;
	pthread_mutex_unlock(&lockBlacklist);
	if (verboseOn) {
    printf("\n **************************************\n * URL Blacklist violation Detected\n ");
    printMac(ethhdr);
    printf(" * Source IP/TCP port: %s:%d\n * Destination IP/TCP port: %s:%d\n ",ipSource, tcpSource, ipDest, tcpDest);
    printf(" **************************************\n");
	}
}

// Print an ip packet
void printPacket(struct ether_header *ethhdr, char* ipSource, char* ipDest, int tcpSource, int tcpDest)
{
  printf("\n **************************************\n * Packet :\n ");
  printMac(ethhdr);
  printf(" * Source IP/TCP port: %s:%d\n * Destination IP/TCP port: %s:%d\n ",ipSource, tcpSource, ipDest, tcpDest);
  printf(" **************************************\n");
}

// print the payload of the blacklisted url request if -v
void print_payload(const unsigned char *payload, int length) {
	int i;
	// Only print visible ascii characters and newlines.
	printf(" * Payload:\n * ");
	for (i = 0; i < length; i++) {
		if (payload[i] > 31 && payload[i] < 127) {
			printf("%c", payload[i]);
		} else if (payload[i] == 10) {
			printf("\n * ");
		}
	}
	printf("\n **************************************\n");
}

// Print the report of malicious activity
void print_resume() {
	// Destroy mutexes, program's ended execution.
  pthread_mutex_destroy(&lockArpReply);
	pthread_mutex_destroy(&lockXmas);
	pthread_mutex_destroy(&lockBlacklist);
	// Print the report
	printf("\n **************************************\n * Intrusion Detection Report:\n"
			" * ARP Poison: %lu\n"
			" * XMAS Tree Scans: %lu\n"
			" * URL Blacklist Violations: %lu\n"
			" **************************************\n",
			arpReply, xmas, urlblack
	);
}



void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose)
{
  // set verbose
  verboseOn = verbose;
  // header structs
  struct ether_header *ethhdr = (struct ether_header *) packet;
  struct ip *iphdr;
  struct tcphdr *tcphdr;
  struct ether_arp *arphdr;
  // tcp destination and source ports
  u_int tcpSource, tcpDest;
  // Ip ports
  char ipSource[INET_ADDRSTRLEN];
  char ipDest[INET_ADDRSTRLEN];
  const unsigned char *payload;

  // length of packet
  int length = header->len;
  // Check if it is an IP or ARP packet
  switch (ntohs(ethhdr->ether_type))
  {
    case ETHERTYPE_IP :
      // Found an IP packet
      iphdr = (struct ip*)(packet + sizeof(struct ether_header));

      // Check if this is a TCP packet
      if(iphdr->ip_p == IPPROTO_TCP)
      {
        tcphdr = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

        // Get ports and addresses for source and destination
        tcpSource = ntohs(tcphdr->dest);
        tcpDest = ntohs(tcphdr->source);
        inet_ntop(AF_INET,&(iphdr->ip_src), ipSource, INET_ADDRSTRLEN);
        inet_ntop(AF_INET,&(iphdr->ip_dst), ipDest, INET_ADDRSTRLEN);

        // Check for Xmasx packets (impossible for the ARP to be one)
        if (tcphdr->fin && tcphdr->psh && tcphdr->urg)
          xmasDetected(ethhdr, ipSource, ipDest, tcpSource, tcpDest);

        // Check for blacklisted URLs (again impossible when the packet is an ARP)
        if (tcpDest == 80)
        {
          payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
          // Length of the payload
          length = ntohs(iphdr->ip_len) - (sizeof(struct ip) + sizeof(struct tcphdr));

          if (strstr((char *) payload, "www.bbc.co.uk") != NULL)
          {
            urlDetected(ethhdr, ipSource, ipDest, tcpSource, tcpDest);
            if (verboseOn)
              print_payload(payload, length);
          }
        }
        // Debug : test the packet parsing
        // if (verboseOn)
        //   printPacket
      }
      break;
    case ETHERTYPE_ARP :
      // found an ARP file
      arphdr = (struct ether_arp *) (packet + sizeof(struct ether_header));
      // This is an ARP packet, we have to check if it is a reply as these could be malicious
      if (arphdr->arp_op == htons(ARPOP_REPLY))
        arpReplyDetected(ethhdr);
      break;
  }
}
