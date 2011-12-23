#ifndef _TRACEDUMP_H_
#define _TRACEDUMP_H_

#include <stdio.h>
#include <libpjf/lib.h>
#include <sys/types.h>
#include <sys/socket.h>

/* TODO: think about a speed-up for multiple sendto() calls from same {pid,fd} pairs */

struct tracedump;
struct pid;
struct sock;
struct port;

/** Holds global program information */
struct tracedump {
	mmatic *mm;                           /**< global memory */
	pid_t pid;                            /**< parent pid */

	/* structures for ptrace */
	thash *pids;                          /**< traced PIDs: (int pid)->(struct pid) */
	thash *socks;                         /**< sockets: (int socknum)->(struct sock) */

	/* structures for /proc/net/{tcp,udp} garbage collector */
	thash *tcp_ports;                     /**< monitored TCP ports: (int port)->(struct port) */
	thash *udp_ports;                     /**< monitored UDP ports: (int port)->(struct port) */
};

/** Represents a process */
// int td_getsocknum(struct tracedump *td, int pid, int fd) -> readlink(/proc/<pid>/fd/<fd>
struct pid {
	int pid;                              /**< process ID */

	bool in_socketcall;                   /**< true if in syscall 102 and its bind(), sendto() or connect() */
	int code;                             /**< socketcall code */
	int fd;                               /**< first argument - if in bind(), sendto() or connect() */
};

/** Represents a socket */
/* td_new_socket(struct tracedump *td, struct pid *stopped_pid, int socknum);
 * domain: getsockname()->sa_family
 * type: getsockopt(s, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
 * port: getsockname()->ntohs(sin_port) */
struct sock {
	int socknum;                          /**< socket number */

	int domain;                           /**< socket domain, eg. AF_INET */
	int type;                             /**< socket type, e.g SOCK_STREAM or SOCK_DGRAM */
	uint16_t portnum;                     /**< if TCP or UDP: local port number */
};

/** Represents a monitored port */
struct port {
	struct timeval since;                 /**< time when it was inserted into the BPF filter */
	struct timeval last;                  /**< time when it was last seen in relevant procfs socket list */
	int socknum;                          /**< socknum seen on last procfs read */
};

#endif
