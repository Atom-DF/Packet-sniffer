#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H


void free_pcap_handle();

void sniff(char *interface, int verbose);

void dump(const unsigned char *data, int length);

#endif
