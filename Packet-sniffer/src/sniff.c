#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include "dispatch.h"
#include "analysis.h"

// easy access to verbose
int gVerbose = 0;

// easily free the handle
pcap_t *pcap_handle;

void free_pcap_handle()
{
  //Close the connection
  pcap_close(pcap_handle);
}

// Use this function to simplify the dispatching and so that we can pass any args
// and not throught the pcap_lap data agaument (which is tedious)
void pre_dispatch(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  dispatch((const struct pcap_pkthdr *) header, (u_char *) packet, gVerbose);
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  // there is no way i can check if strdup is called without editing main.c
  // even though I would need to free its return

  // Check if verbose should be active
  if (verbose)
    gVerbose = verbose;
  // Create the pcap_handle
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
  // Check if the handle is created correctly
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  // This is to try to prevent to spam the log of entering and leaving
  // promiscious mode
  pcap_set_promisc(pcap_handle, 0);
  // Check If the loop works, 0 means it will run infinitely
  if (pcap_loop(pcap_handle, 0, pre_dispatch, NULL) != 0)
  {
    printf("error in pcap loop\n");
    exit(EXIT_FAILURE);
  }
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;

  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
