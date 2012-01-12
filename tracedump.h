/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#ifndef _TRACEDUMP_H_
#define _TRACEDUMP_H_

#include <stdio.h>
#include <libpjf/lib.h>
#include <sys/types.h>
#include <sys/socket.h>

struct tracedump;
struct pid;
struct sock;
struct port;

#include "inject.h"
#include "ptrace.h"
#include "utils.h"

/** Holds global program information */
struct tracedump {
	mmatic *mm;                           /**< global memory */

	pid_t pid;                            /**< monitored pid (root) */
	struct pid *sp;                       /**< pid cache */

	/* structures for ptrace */
	thash *pids;                          /**< traced PIDs: (int pid)->(struct pid) */
	thash *socks;                         /**< sockets: (int socknum)->(struct sock) */

	/* structures for /proc/net/{tcp,udp} garbage collector */
	thash *tcp_ports;                     /**< monitored TCP ports: (int port)->(struct port) */
	thash *udp_ports;                     /**< monitored UDP ports: (int port)->(struct port) */
};

/** Represents a process */
struct pid {
	int pid;                              /**< process ID */

	bool in_socketcall;                   /**< true if in syscall 102 and its bind(), sendto() or connect() */
	int code;                             /**< socketcall code */
	struct sock *ss;                      /**< cache */
};

/** Represents a socket */
struct sock {
	int socknum;                          /**< socket number */
	int type;                             /**< socket type, ie. SOCK_STREAM or SOCK_DGRAM */
	uint16_t port;                        /**< if TCP or UDP: local port number */
};

/** Represents a monitored port */
struct port {
	struct timeval since;                 /**< time when it was inserted into the BPF filter */
	struct timeval last;                  /**< time when it was last seen in relevant procfs socket list */
	int socknum;                          /**< socknum seen on last procfs read */
};

#endif