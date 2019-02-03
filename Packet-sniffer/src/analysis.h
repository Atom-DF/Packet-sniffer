#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

void print_resume();

void analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose);

#endif
