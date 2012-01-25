/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#ifndef _PCAP_H_
#define _PCAP_H_

#include <pthread.h>
#include "tracedump.h"

/** Represents internal data */
struct pcap {
	int fd;                /**< sniffing socket */
	pthread_t reader;      /**< reader thread */
	FILE *fp;              /**< PCAP file */
};

/* From http://wiki.wireshark.org/Development/LibpcapFileFormat */
#ifndef PCAP_MAGIC_NUMBER
#define PCAP_MAGIC_NUMBER 0xa1b2c3d4
#endif
#ifndef LINKTYPE_LINUX_SLL
#define LINKTYPE_LINUX_SLL 113
#endif
struct pcap_file_hdr {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
};
struct pcap_pkt_hdr {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
};
struct pcap_sll_hdr {
	uint16_t sll_pkttype;
	uint16_t sll_hatype;
	uint16_t sll_halen;
	uint8_t  sll_addr[8];
	uint16_t sll_protocol;
};

/** Initialize PCAP and set the "null filter" */
void pcap_init(struct tracedump *td);

/** Reverse of pcap_init() */
void pcap_deinit(struct tracedump *td);

/** Update the BPF filter on the sniffer socket */
void pcap_update(struct tracedump *td);

#endif
