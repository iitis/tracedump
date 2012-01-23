/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#ifndef _INJECT_H_
#define _INJECT_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <netinet/in.h>
#include <sys/user.h>
#include <libpjf/lib.h>

#include "tracedump.h"

/** Circumvent an on-going socketcall
 *
 * Implemented by calling socketcall with an invalid subcode, which will result in an -EINVAL.
 * This will put the traced process in normal state, ie. executing the code under EIP, which is
 * required for the inject_*() functions to work properly.
 */
void inject_escape_socketcall(struct tracedump *td, struct pid *sp);

/** Cancel inject_escape_socketcall() effects
 *
 * This function will execute the whole socketcall until it finishes
 */
void inject_restore_socketcall(struct tracedump *td, struct pid *sp);

/** Argument type used in _inject_socketcall */
enum arg_type {
	AT_LAST = 0,   /**< it was the last argument */
	AT_VALUE,      /**< pass the value */
	AT_MEM_IN,     /**< memory buffer: an input */
	AT_MEM_INOUT   /**< memory buffer: an input and an output */
};

/** Inject socketcall() into running process
 *
 * Supports variable list of arguments to socketcall(), each may be of different kind
 *
 * @param td              tracedump root
 * @param pid             process id
 * @param sc_code         socketcall subcode (see include/linux/net.h)
 * @param varg1           enum arg_type
 * @param varg2           uint32_t: memory size or a value
 * @param varg3           OPTIONAL void *: address of the memory
 * @param ...
 * @param 1, 0, 1
 * @return                socketcall() return code
 */
int32_t inject_socketcall(struct tracedump *td, struct pid *sp, uint32_t sc_code, ...);

/** Inject bind(fd, {AF_INET, INADDR_ANY, .port = 0}, 16) */
static inline int inject_autobind(struct tracedump *td, struct pid *sp, int fd)
{
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port   = 0,
		.sin_addr   = { INADDR_ANY }
	};

	return inject_socketcall(td, sp, SYS_BIND,
		AT_VALUE, fd,
		AT_MEM_IN, sizeof sa, &sa,
		AT_VALUE, sizeof sa,
		AT_LAST);
}

/** Inject getsockname(fd, sa, 16)
 * @retval -2    socket not AF_INET */
static inline int inject_getsockname_in(struct tracedump *td, struct pid *sp, int fd, struct sockaddr_in *sa)
{
	socklen_t size = sizeof *sa;
	int rc;

	rc = inject_socketcall(td, sp, SYS_GETSOCKNAME,
		AT_VALUE, fd,
		AT_MEM_INOUT, sizeof *sa, sa,
		AT_MEM_INOUT, sizeof size, &size,
		AT_LAST);

	if (size != sizeof *sa || sa->sin_family != AF_INET)
		return -2;
	else
		return rc;
}

/** Inject getsockopt() */
static inline int inject_getsockopt(struct tracedump *td, struct pid *sp,
	int fd, int level, int optname,
	void *optval, socklen_t *optlen)
{
	return inject_socketcall(td, sp, SYS_GETSOCKOPT,
		AT_VALUE, fd,
		AT_VALUE, level,
		AT_VALUE, optname,
		AT_MEM_INOUT, *optlen, optval,
		AT_MEM_INOUT, sizeof(socklen_t), optlen,
		AT_LAST);
}

#endif
