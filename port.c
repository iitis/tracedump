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

	td = (struct tracedump *) arg;
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGINT);
	pthread_sigmask(SIG_SETMASK, &ss, NULL);

	while (1) {
		/* TODO: read list of active tcp/udp ports */

		pthread_mutex_lock(&td->mutex_ports);
		printf("yummie yummie\n");
		/* TODO: remove old tcp/udp ports */
		pthread_mutex_unlock(&td->mutex_ports);

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
	} else {
		dbg(1, "port %d/%s already exists\n", ss->port,
			ss->type == SOCK_STREAM ? "TCP" : "UDP");
	}

	gettimeofday(&sp->last, NULL);
	sp->local = local;
	sp->socknum = ss->socknum;

	dbg(3, "port %d/%s added\n", ss->port,
		ss->type == SOCK_STREAM ? "TCP" : "UDP");

	pthread_mutex_unlock(&ss->td->mutex_ports);
}
