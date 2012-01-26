/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#ifndef _TRACEDUMP_H_
#define _TRACEDUMP_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/net.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>

#include <libpjf/lib.h>

#define TRACEDUMP_VERSION "0.5"

struct tracedump;
struct pid;
struct sock;
struct port;

#include "inject.h"
#include "ptrace.h"
#include "pcap.h"
#include "pid.h"
#include "port.h"

/** Holds global program information */
struct tracedump {
	mmatic *mm;                           /**< global memory */
	jmp_buf jmp;                          /**< for exception handling */

	/* options */
	struct {
		char **src;                       /**< packet source (pointer on argv) */
		int srclen;                       /**< number of elements in src[] */
		char *outfile;                    /**< path to output file */
		int snaplen;                      /**< PCAP snaplen */
	} opts;

	/* structures for process tracing */
	struct pid *sp;                       /**< pid cache */
	thash *pids;                          /**< traced PIDs: (int pid)->(struct pid) */
	thash *socks;                         /**< sockets: (int socknum)->(struct sock) */

	/* structures for port tracking */
	pthread_mutex_t mutex_ports;          /**< guards tcp_ports and udp_ports */
	pthread_t thread_gc;                  /**< garbage collector thread */
	thash *tcp_ports;                     /**< monitored TCP ports: (int port)->(struct port) */
	thash *udp_ports;                     /**< monitored UDP ports: (int port)->(struct port) */

	/* structures for packet capture */
	struct pcap *pc;                      /**< PCAP data */
};

/** Represents a process */
struct pid {
	struct tracedump *td;                 /**< path to the root data structure */
	int pid;                              /**< process ID */

	bool in_socketcall;                   /**< true if in syscall 102 and its bind(), sendto() or connect() */
	int code;                             /**< socketcall code */
	struct sock *ss;                      /**< cache */

	struct user_regs_struct regs;         /**< regs backup */
};

/** Represents a socket */
struct sock {
	struct tracedump *td;                 /**< path to the root data structure */
	int socknum;                          /**< socket number */
	int type;                             /**< socket type, ie. SOCK_STREAM or SOCK_DGRAM */
	unsigned long port;                   /**< if TCP or UDP: port number */
};

/** Represents a monitored port */
struct port {
	struct timeval since;                 /**< time when it was first seen */
	bool local;                           /**< local port if true, remote port otherwise */
	int socknum;                          /**< socknum seen on last procfs read */
};

/* exceptions */
#define EXCEPTION(td, code, arg) longjmp(td->jmp, ((code) & 0xffff) | ((arg) << 16))
#define EXC_PTRACE 1

/* assumes 32-bits in int */
#define EXC_CODE(i) ((i) & 0xffff)
#define EXC_ARG(i) ((i) >> 16)

#endif
