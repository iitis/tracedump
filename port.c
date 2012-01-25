/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#include "tracedump.h"

static void *gc_thread(void *arg)
{
	struct tracedump *td;
	sigset_t ss;
	uint8_t *tcp = NULL, *udp = NULL;

	td = (struct tracedump *) arg;
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGINT);
	pthread_sigmask(SIG_SETMASK, &ss, NULL);

	while (1) {
		/* read list of active tcp/udp ports */
		tcp = port_list(td, true);
		udp = port_list(td, false);
		if (!tcp || !udp) {
			dbg(1, "gc: reading tcp/udp ports failed\n");
			goto next;
		}

		pthread_mutex_lock(&td->mutex_ports);
		printf("yummie yummie\n");
		/* TODO: remove old tcp/udp ports */
		/* TODO: autobound TCP ports not visible on list */
		pthread_mutex_unlock(&td->mutex_ports);

next:
		if (tcp) mmatic_free(tcp);
		if (udp) mmatic_free(udp);
		sleep(3);
	}

	return NULL;
}

/*******************************************************************/

void port_init(struct tracedump *td)
{
	int i;

	i = pthread_create(&td->thread_gc, NULL, gc_thread, td);
	if (i != 0)
		die("pthread_create(gc_thread) failed with error %d\n", i);
}

void port_deinit(struct tracedump *td)
{
	/* close the reader and wait for it */
	pthread_cancel(td->thread_gc);
	pthread_join(td->thread_gc, NULL);
}

void port_add(struct sock *ss, bool local)
{
	struct port *sp;
	thash *ports;

	pthread_mutex_lock(&ss->td->mutex_ports);

	if (ss->type == SOCK_DGRAM)
		ports = ss->td->udp_ports;
	else if (ss->type == SOCK_STREAM)
		ports = ss->td->tcp_ports;
	else
		die("invalid ss->type\n");

	sp = thash_uint_get(ports, ss->port);
	if (!sp) {
		sp = mmatic_zalloc(ss->td->mm, sizeof *sp);
		thash_uint_set(ports, ss->port, sp);
	}

	gettimeofday(&sp->last, NULL);
	sp->local = local;
	sp->socknum = ss->socknum;

	dbg(3, "port %d/%s added\n", ss->port,
		ss->type == SOCK_STREAM ? "TCP" : "UDP");

	pthread_mutex_unlock(&ss->td->mutex_ports);
}

void *port_list(struct tracedump *td, bool tcp)
{
	char *path;
	char buf[BUFSIZ], *ptr1, *ptr2;
	FILE *fp;
	uint8_t *list;
	unsigned long port;

	path = tcp ? "/proc/net/tcp" : "/proc/net/udp";

	fp = fopen(path, "r");
	if (!fp) {
		dbg(1, "fopen(%s): %s\n", path, strerror(errno));
		return NULL;
	}

	/* a bitmask 1: active, 0: inactive */
	list = mmatic_zalloc(td->mm, UINT16_MAX / sizeof(uint8_t));

	while (fgets(buf, sizeof buf, fp)) {
		/* first : */
		ptr1 = strchr(buf, ':');
		if (!ptr1) continue;
		ptr1++;

		/* second : */
		ptr1 = strchr(ptr1, ':');
		if (!ptr1) continue;
		ptr1++;

		/* space */
		ptr2 = strchr(ptr1, ' ');
		if (!ptr2) continue;
		ptr2[0]  = '\0';

		/* translate */
		port = strtol(ptr1, NULL, 16);
		PORT_SET(list, port);
	}

	fclose(fp);
	return list;
}
