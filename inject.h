/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#ifndef _INJECT_H_
#define _INJECT_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <netinet/in.h>
#include <sys/user.h>


/** Holds data used by the injection code */
struct inject {
	char *code;               /**< machine code, word-aligned; may be platform-dependent */
	int len;                  /**< code length, from code segment */
	int len4;                 /**< len aligned to words (4 bytes) */

	int data_offset;          /**< offset to data (see asm code) */
	uint32_t *data;           /**< pointer on code + data_offset */

	int addr_offset;          /**< offset to socket address */
	struct sockaddr_in *addr; /**< pointer on code + si_offset */
};

/** Initialize inject */
struct inject *inject_init(void);

/** Deinitialize inject */
void inject_free(struct inject *si);

/** Inject socketcall() into running process.
 *
 * Supports bind, getsockname, and similar calls
 *
 * @param si              see inject_init()
 * @param sc_code         socketcall subcode (see include/linux/net.h)
 * @param output          copy the result back to sa?
 * @param pid             process id
 * @param fd              file descriptor, local to pid
 * @param sa              socket address
 * @return                socketcall() return code
 */
int32_t _inject_socketcall(struct inject *si, uint32_t sc_code, bool output, pid_t pid,
	int fd, struct sockaddr_in *sa);

/** Inject bind(fd, {AF_INET, INADDR_ANY, .port = 0}, 16) */
static inline int inject_autobind(struct inject *si, pid_t pid, int fd)
{
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port   = 0,
		.sin_addr   = { INADDR_ANY }
	};

	return _inject_socketcall(si, SYS_BIND, false, pid, fd, &sa);
}

/** Inject getsockname(fd, sa, 16) */
static inline int inject_getsockname(struct inject *si, pid_t pid, int fd, struct sockaddr_in *sa)
{
	return _inject_socketcall(si, SYS_GETSOCKNAME, true, pid, fd, sa);
}

#endif
