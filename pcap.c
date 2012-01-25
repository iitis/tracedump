/*
 * Copyright (C) 2011 IITiS PAN Gliwice <www.iitis.pl>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#include <pthread.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include "tracedump.h"

/* enable to check the generated BPF code before sending it to the kernel */
//#define CHECK_BPF

/* static functions */
static void *sniffer_thread(void *arg);
static int gencode_check_ports(thash *ports, bool outbound,
	struct sock_filter *filter, int loc_drop, int loc_accept);
static struct sock_fprog *gencode_alloc(struct tracedump *td);
#ifdef CHECK_BPF
static int sk_chk_filter(struct sock_filter *filter, unsigned int flen);
#endif

void pcap_init(struct tracedump *td)
{
	int i;
	struct sockaddr_ll ll;
	struct pcap_file_hdr ph;

	/* initialize */
	td->pc = mmatic_zalloc(td->mm, sizeof(struct pcap));

	/* open the sniffing socket */
	memset(&ll, 0, sizeof ll);
	ll.sll_family = AF_PACKET;
	td->pc->fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (td->pc->fd == -1)
		die_errno("socket");

	/* open the resultant file */
	td->pc->fp = fopen("dump.pcap", "w"); // TODO
	if (!td->pc->fp) die_errno("fopen");

	/* write the global header */
	ph.magic_number  = PCAP_MAGIC_NUMBER;
	ph.version_major = 2;
	ph.version_minor = 4;
	ph.thiszone      = 0;
	ph.sigfigs       = 0;
	ph.snaplen       = 31337; // TODO
	ph.network       = LINKTYPE_LINUX_SLL;
	fwrite(&ph, sizeof ph, 1, td->pc->fp);

	/* start the reader thread */
	i = pthread_create(&td->pc->reader, NULL, sniffer_thread, td);
	if (i != 0)
		die("pthread_create(sniffer_thread) failed with error %d\n", i);

	/* update the filter */
	pcap_update(td);
}

void pcap_deinit(struct tracedump *td)
{
	/* close the reader and wait for it */
	pthread_cancel(td->pc->reader);
	pthread_join(td->pc->reader, NULL);

	close(td->pc->fd);
	fclose(td->pc->fp);

	/* free the memory */
	mmatic_free(td->pc);
}

void pcap_update(struct tracedump *td)
{
	struct sock_fprog *fp;

	/* generate BPF filter code basing on the current port list */
	pthread_mutex_lock(&td->mutex_ports);
	fp = gencode_alloc(td);
	pthread_mutex_unlock(&td->mutex_ports);

#ifdef CHECK_BPF
	/* verify the code on the user side - useful for debugging */
	sk_chk_filter(fp->filter, fp->len);
#endif

	/* attach the filter */
	if (setsockopt(td->pc->fd, SOL_SOCKET, SO_ATTACH_FILTER, fp, sizeof *fp) != 0)
		die_errno("setsockopt");

	mmatic_free(fp->filter);
	mmatic_free(fp);
}

/****************************************************************************/

void *sniffer_thread(void *arg)
{
	struct tracedump *td;
	int i, snaplen, inclen;
	uint8_t pkt[8192];
	struct pcap_pkt_hdr pp;
	struct pcap_sll_hdr ps;
	struct timeval ts;
	struct sockaddr_ll ll;
	socklen_t len;
	sigset_t ss;

	td = (struct tracedump *) arg;
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGINT);
	pthread_sigmask(SIG_SETMASK, &ss, NULL);

	snaplen = 31337; // TODO

	/* write the packets */
	while ((len = sizeof ll) &&
	       (i = recvfrom(td->pc->fd, pkt, sizeof pkt, 0, (struct sockaddr *) &ll, &len)) > 0) {
		/* drop non-IP frames */
		if (ll.sll_protocol != htons(ETH_P_IP))
			continue;

		/* get packet timestamp */
		if (ioctl(td->pc->fd, SIOCGSTAMP, &ts) == -1)
			die_errno("ioctl");

		/* write the PCAP header */
		inclen = MIN(snaplen, i);
		pp.ts_sec   = ts.tv_sec;
		pp.ts_usec  = ts.tv_usec;
		pp.orig_len = i + sizeof ps;
		pp.incl_len = inclen + sizeof ps;
		fwrite(&pp, sizeof pp, 1, td->pc->fp);

		/* write the SSL header */
		ps.sll_pkttype  = ntohs(ll.sll_pkttype);
		ps.sll_hatype   = ntohs(ll.sll_hatype);
		ps.sll_halen    = ntohs(ll.sll_halen);
		memcpy(ps.sll_addr, ll.sll_addr, 8);
		ps.sll_protocol = ll.sll_protocol;
		fwrite(&ps, sizeof ps, 1, td->pc->fp);

		/* write the packet */
		fwrite(pkt, inclen, 1, td->pc->fp);
	}

	die_errno("recv()");
	return NULL;
}

/****************************************************************************/
/******************************************************* BPF code generator */
/****************************************************************************/

/* BPF code template
 *
 * BPF code map
 * ============
 *
 * 1. check_ip
 *    - __DROP -> not IP or a fragment -> goto drop
 *    - transport_offset loaded in X
 * 2. check_type_outbound
 *    - __RET1 -> not this type -> goto 5.
 *    - __RET2 -> outgoing TCP -> goto 4.
 *    - __DROP -> not tcp/udp -> goto drop
 * 3. OUT: check_ports UDP
 *    - __PORT (twice): ports to check
 *    - __ACCEPT -> goto accept
 *    - __DROP -> goto drop
 * 4. OUT: check_ports TCP
 * 5. check_type_inbound
 *    - __RET1 -> inbound TCP -> goto 7.
 *    - __DROP -> not tcp/udp -> goto drop
 * 6. IN: check_ports UDP <- REVERSE in-out!
 * 7. IN: check_ports TCP <- REVERSE in-out!
 * 8. end:
 *    [0] accept
 *    [1] drop
 *
 * Locations required to be computed before code construction:
 *   total_length = 5+5+3+3+7+3+3+ 2*#tcp + 2*#udp + 2
 *   "drop"   -> total length - 1   == "8"+1
 *   "accept" -> total_length - 2   == "8"
 *   "8"      -> "7" + 3 + number of TCP ports
 *   "7"      -> "6" + 3 + number of UDP ports
 *   "6"      -> "5" + 7
 *   "5"      -> "4" + 3 + number of TCP ports
 *   "4"      -> "3" + 3 + number of UDP ports
 *   "3"      -> "2" + 5
 *   "2"      -> "1" + 5
 *   "1"      -> 0
 *
 * Value of location depends on the current position in code
 * =========================================================
 */

#define __ACCEPT ((uint8_t)  -1)
#define __DROP   ((uint8_t)  -2)
#define __RET1   ((uint8_t)  -3)
#define __RET2   ((uint8_t)  -4)

static struct sock_filter check_ip[] = {
	/* check IPv4 */
	BPF_STMT(BPF_LD  + BPF_ABS,           SKF_AD_OFF + SKF_AD_PROTOCOL),
	BPF_JUMP(BPF_JMP + BPF_JEQ,           ETH_P_IP, 0, __DROP),

	/* check if fragment offset == 0 */
	BPF_STMT(BPF_LD  + BPF_H + BPF_ABS,   SKF_NET_OFF + 6),
	BPF_JUMP(BPF_JMP + BPF_JSET,          0x1fff, __DROP, 0),

	/* load the offset of the transport header -> X */
	BPF_STMT(BPF_LDX + BPF_B + BPF_MSH,   SKF_NET_OFF + 0),
};

static struct sock_filter check_type_outbound[] = {
	/* check direction */
	BPF_STMT(BPF_LD  + BPF_H + BPF_ABS,   SKF_AD_OFF + SKF_AD_PKTTYPE),
	BPF_JUMP(BPF_JMP + BPF_JEQ,           PACKET_OUTGOING, 0, __RET1),

	/* load transport protocol: IP+9 */
	BPF_STMT(BPF_LD  + BPF_B + BPF_ABS,   SKF_NET_OFF + 9),
	BPF_JUMP(BPF_JMP + BPF_JEQ,           IPPROTO_TCP, __RET2, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ,           IPPROTO_UDP, 0, __DROP),
};

static struct sock_filter check_type_inbound[] = {
	BPF_STMT(BPF_LD  + BPF_H + BPF_ABS,   SKF_AD_OFF + SKF_AD_PKTTYPE),
	BPF_JUMP(BPF_JMP + BPF_JEQ,           PACKET_HOST,      2, __DROP),
	BPF_JUMP(BPF_JMP + BPF_JEQ,           PACKET_BROADCAST, 1, __DROP),
	BPF_JUMP(BPF_JMP + BPF_JEQ,           PACKET_MULTICAST, 0, __DROP),

	BPF_STMT(BPF_LD  + BPF_B + BPF_ABS,   SKF_NET_OFF + 9),
	BPF_JUMP(BPF_JMP + BPF_JEQ,           IPPROTO_TCP, __RET1, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ,           IPPROTO_UDP, 0, __DROP),
};

/* check local and remote ports */
static struct sock_filter check_ports[3] = {
	BPF_STMT(BPF_LD  + BPF_H + BPF_IND,   SKF_NET_OFF + 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ,           0, __ACCEPT, 0),
	BPF_STMT(BPF_JMP + BPF_JA,            __DROP),
};

static struct sock_filter end[] = {
	BPF_STMT(BPF_RET,                     UINT16_MAX),
	BPF_STMT(BPF_RET,                     0)
};

static int gencode_check_ports(thash *ports, bool outbound,
	struct sock_filter *filter, int loc_drop, int loc_accept)
{
	int i = 0, j;
	struct port *sp;
	unsigned long port;

	if (thash_count(ports) == 0) {
		/* no ports - just drop */
		for (j = 0; j < 3; j++) {
			memcpy(filter+i, &check_ports[2], sizeof *check_ports);
			filter[i].k = loc_drop - i - 1;
			i++;
		}

		return i;
	}

	/* check local ports -> source port */
	memcpy(filter+i, &check_ports[0], sizeof *check_ports);
	filter[i].k += 0; /* in UDP/TCP src port is @ offset 0 */
	i++;

	thash_reset(ports);
	while ((sp = thash_uint_iter(ports, &port))) {
		if (sp->local != outbound) continue;

		memcpy(filter+i, &check_ports[1], sizeof *check_ports);
		filter[i].k = port;
		filter[i].jt = loc_accept - i - 1;
		i++;
	}

	/* check remote ports -> destination port */
	memcpy(filter+i, &check_ports[0], sizeof *check_ports);
	filter[i].k += 2; /* in UDP/TCP dst port is @ offset 2 */
	i++;

	thash_reset(ports);
	while ((sp = thash_uint_iter(ports, &port))) {
		if (sp->local == outbound) continue;

		memcpy(filter+i, &check_ports[1], sizeof *check_ports);
		filter[i].k = port;
		filter[i].jt = loc_accept - i - 1;
		i++;
	}

	/* if nothing matched, drop */
	memcpy(filter+i, &check_ports[2], sizeof *check_ports);
	filter[i].k = loc_drop - i - 1;
	i++;

	return i;
}

static struct sock_fprog *gencode_alloc(struct tracedump *td)
{
	struct sock_fprog *fp;
	int i, j;

	/* code locations */
	int
	loc_1      = 0,
	loc_2      = loc_1 + N(check_ip),
	loc_3      = loc_2 + N(check_type_outbound),
	loc_4      = loc_3 + N(check_ports) + thash_count(td->udp_ports),
	loc_5      = loc_4 + N(check_ports) + thash_count(td->tcp_ports),
	loc_6      = loc_5 + N(check_type_inbound),
	loc_7      = loc_6 + N(check_ports) + thash_count(td->udp_ports),
	loc_accept = loc_7 + N(check_ports) + thash_count(td->tcp_ports),
	loc_drop   = loc_accept + 1;

	/* allocate memory */
	fp = mmatic_zalloc(td->mm, sizeof(struct sock_fprog));
	fp->len = loc_drop + 1;
	fp->filter = mmatic_zalloc(td->mm, sizeof(struct sock_filter) * fp->len);

/*printf("loc_1=%d, loc_2=%d, loc_3=%d, loc_4=%d, loc_5=%d, loc_6=%d, loc_7=%d, loc_drop=%d, loc_accept=%d\n",
loc_1, loc_2, loc_3, loc_4, loc_5,
loc_6, loc_7, loc_drop, loc_accept);*/

	/*
	 * Fill
	 */
	i = 0;

#define SUBST_JMP(from, to)                    \
	if (fp->filter[i+j].jt == (from))          \
		fp->filter[i+j].jt = (to) - i - j - 1; \
	if (fp->filter[i+j].jf == (from))          \
		fp->filter[i+j].jf = (to) - i - j - 1;

	/* 1. check_ip */
	memcpy(fp->filter + i, check_ip, sizeof check_ip);
	for (j = 0; j < N(check_ip); j++) {
		SUBST_JMP(__DROP, loc_drop);
	}
	i += j;

	/* 2. check_type_outbound */
	memcpy(fp->filter + i, check_type_outbound, sizeof check_type_outbound);
	for (j = 0; j < N(check_type_outbound); j++) {
		SUBST_JMP(__RET1, loc_5);
		SUBST_JMP(__RET2, loc_4);
		SUBST_JMP(__DROP, loc_drop);
	}
	i += j;

	/* 3. OUTBOUND: check_ports: td->udp_ports */
	i += gencode_check_ports(td->udp_ports, true, fp->filter+i, loc_drop-i, loc_accept-i);

	/* 4. OUTBOUND: check_ports: td->tcp_ports */
	i += gencode_check_ports(td->tcp_ports, true, fp->filter+i, loc_drop-i, loc_accept-i);

	/* 5. check_type_inbound */
	memcpy(fp->filter + i, check_type_inbound, sizeof check_type_inbound);
	for (j = 0; j < N(check_type_inbound); j++) {
		SUBST_JMP(__RET1, loc_7);
		SUBST_JMP(__DROP, loc_drop);
	}
	i += j;

	/* 6. INBOUND: check_ports: td->udp_ports */
	i += gencode_check_ports(td->udp_ports, false, fp->filter+i, loc_drop-i, loc_accept-i);

	/* 7. INBOUND: check_ports: td->tcp_ports */
	i += gencode_check_ports(td->tcp_ports, false, fp->filter+i, loc_drop-i, loc_accept-i);

	/* 8. end */
	memcpy(fp->filter + i, end, sizeof end);
	i += N(end);

	return fp;
}

/****************************************************************************/
/**************** modified BPF check code from the Linux kernel of 5/5/2011 */
/****************************************************************************/
#ifdef CHECK_BPF

#include <linux/types.h>
#include <errno.h>
#define u8 uint8_t
#define u16 uint16_t

enum {
	BPF_S_RET_K = 1, BPF_S_RET_A, BPF_S_ALU_ADD_K, BPF_S_ALU_ADD_X, BPF_S_ALU_SUB_K,
	BPF_S_ALU_SUB_X, BPF_S_ALU_MUL_K, BPF_S_ALU_MUL_X, BPF_S_ALU_DIV_X, BPF_S_ALU_AND_K,
	BPF_S_ALU_AND_X, BPF_S_ALU_OR_K, BPF_S_ALU_OR_X, BPF_S_ALU_LSH_K, BPF_S_ALU_LSH_X,
	BPF_S_ALU_RSH_K, BPF_S_ALU_RSH_X, BPF_S_ALU_NEG, BPF_S_LD_W_ABS, BPF_S_LD_H_ABS,
	BPF_S_LD_B_ABS, BPF_S_LD_W_LEN, BPF_S_LD_W_IND, BPF_S_LD_H_IND, BPF_S_LD_B_IND,
	BPF_S_LD_IMM, BPF_S_LDX_W_LEN, BPF_S_LDX_B_MSH, BPF_S_LDX_IMM, BPF_S_MISC_TAX,
	BPF_S_MISC_TXA, BPF_S_ALU_DIV_K, BPF_S_LD_MEM, BPF_S_LDX_MEM, BPF_S_ST,
	BPF_S_STX, BPF_S_JMP_JA, BPF_S_JMP_JEQ_K, BPF_S_JMP_JEQ_X, BPF_S_JMP_JGE_K,
	BPF_S_JMP_JGE_X, BPF_S_JMP_JGT_K, BPF_S_JMP_JGT_X, BPF_S_JMP_JSET_K, BPF_S_JMP_JSET_X,
	BPF_S_ANC_PROTOCOL, BPF_S_ANC_PKTTYPE, BPF_S_ANC_IFINDEX, BPF_S_ANC_NLATTR, BPF_S_ANC_NLATTR_NEST,
	BPF_S_ANC_MARK, BPF_S_ANC_QUEUE, BPF_S_ANC_HATYPE, BPF_S_ANC_RXHASH, BPF_S_ANC_CPU,
};

static int check_load_and_stores(struct sock_filter *filter, int flen)
{
	u16 *masks, memvalid = 0; /* one bit per cell, 16 cells */
	int pc, ret = 0;

	masks = malloc(flen * sizeof(*masks));
	memset(masks, 0xff, flen * sizeof(*masks));

	for (pc = 0; pc < flen; pc++) {
		memvalid &= masks[pc];

		switch (filter[pc].code) {
		case BPF_S_ST:
		case BPF_S_STX:
			memvalid |= (1 << filter[pc].k);
			break;
		case BPF_S_LD_MEM:
		case BPF_S_LDX_MEM:
			if (!(memvalid & (1 << filter[pc].k))) {
				ret = -EINVAL;
				goto error;
			}
			break;
		case BPF_S_JMP_JA:
			/* a jump must set masks on target */
			masks[pc + 1 + filter[pc].k] &= memvalid;
			memvalid = ~0;
			break;
		case BPF_S_JMP_JEQ_K:
		case BPF_S_JMP_JEQ_X:
		case BPF_S_JMP_JGE_K:
		case BPF_S_JMP_JGE_X:
		case BPF_S_JMP_JGT_K:
		case BPF_S_JMP_JGT_X:
		case BPF_S_JMP_JSET_X:
		case BPF_S_JMP_JSET_K:
			/* a jump must set masks on targets */
			masks[pc + 1 + filter[pc].jt] &= memvalid;
			masks[pc + 1 + filter[pc].jf] &= memvalid;
			memvalid = ~0;
			break;
		}
	}
error:
	free(masks);
	return ret;
}

static int sk_chk_filter(struct sock_filter *filter, unsigned int flen)
{
	/*
	 * Valid instructions are initialized to non-0.
	 * Invalid instructions are initialized to 0.
	 */
	static const u8 codes[] = {
		[BPF_ALU|BPF_ADD|BPF_K]  = BPF_S_ALU_ADD_K,
		[BPF_ALU|BPF_ADD|BPF_X]  = BPF_S_ALU_ADD_X,
		[BPF_ALU|BPF_SUB|BPF_K]  = BPF_S_ALU_SUB_K,
		[BPF_ALU|BPF_SUB|BPF_X]  = BPF_S_ALU_SUB_X,
		[BPF_ALU|BPF_MUL|BPF_K]  = BPF_S_ALU_MUL_K,
		[BPF_ALU|BPF_MUL|BPF_X]  = BPF_S_ALU_MUL_X,
		[BPF_ALU|BPF_DIV|BPF_X]  = BPF_S_ALU_DIV_X,
		[BPF_ALU|BPF_AND|BPF_K]  = BPF_S_ALU_AND_K,
		[BPF_ALU|BPF_AND|BPF_X]  = BPF_S_ALU_AND_X,
		[BPF_ALU|BPF_OR|BPF_K]   = BPF_S_ALU_OR_K,
		[BPF_ALU|BPF_OR|BPF_X]   = BPF_S_ALU_OR_X,
		[BPF_ALU|BPF_LSH|BPF_K]  = BPF_S_ALU_LSH_K,
		[BPF_ALU|BPF_LSH|BPF_X]  = BPF_S_ALU_LSH_X,
		[BPF_ALU|BPF_RSH|BPF_K]  = BPF_S_ALU_RSH_K,
		[BPF_ALU|BPF_RSH|BPF_X]  = BPF_S_ALU_RSH_X,
		[BPF_ALU|BPF_NEG]        = BPF_S_ALU_NEG,
		[BPF_LD|BPF_W|BPF_ABS]   = BPF_S_LD_W_ABS,
		[BPF_LD|BPF_H|BPF_ABS]   = BPF_S_LD_H_ABS,
		[BPF_LD|BPF_B|BPF_ABS]   = BPF_S_LD_B_ABS,
		[BPF_LD|BPF_W|BPF_LEN]   = BPF_S_LD_W_LEN,
		[BPF_LD|BPF_W|BPF_IND]   = BPF_S_LD_W_IND,
		[BPF_LD|BPF_H|BPF_IND]   = BPF_S_LD_H_IND,
		[BPF_LD|BPF_B|BPF_IND]   = BPF_S_LD_B_IND,
		[BPF_LD|BPF_IMM]         = BPF_S_LD_IMM,
		[BPF_LDX|BPF_W|BPF_LEN]  = BPF_S_LDX_W_LEN,
		[BPF_LDX|BPF_B|BPF_MSH]  = BPF_S_LDX_B_MSH,
		[BPF_LDX|BPF_IMM]        = BPF_S_LDX_IMM,
		[BPF_MISC|BPF_TAX]       = BPF_S_MISC_TAX,
		[BPF_MISC|BPF_TXA]       = BPF_S_MISC_TXA,
		[BPF_RET|BPF_K]          = BPF_S_RET_K,
		[BPF_RET|BPF_A]          = BPF_S_RET_A,
		[BPF_ALU|BPF_DIV|BPF_K]  = BPF_S_ALU_DIV_K,
		[BPF_LD|BPF_MEM]         = BPF_S_LD_MEM,
		[BPF_LDX|BPF_MEM]        = BPF_S_LDX_MEM,
		[BPF_ST]                 = BPF_S_ST,
		[BPF_STX]                = BPF_S_STX,
		[BPF_JMP|BPF_JA]         = BPF_S_JMP_JA,
		[BPF_JMP|BPF_JEQ|BPF_K]  = BPF_S_JMP_JEQ_K,
		[BPF_JMP|BPF_JEQ|BPF_X]  = BPF_S_JMP_JEQ_X,
		[BPF_JMP|BPF_JGE|BPF_K]  = BPF_S_JMP_JGE_K,
		[BPF_JMP|BPF_JGE|BPF_X]  = BPF_S_JMP_JGE_X,
		[BPF_JMP|BPF_JGT|BPF_K]  = BPF_S_JMP_JGT_K,
		[BPF_JMP|BPF_JGT|BPF_X]  = BPF_S_JMP_JGT_X,
		[BPF_JMP|BPF_JSET|BPF_K] = BPF_S_JMP_JSET_K,
		[BPF_JMP|BPF_JSET|BPF_X] = BPF_S_JMP_JSET_X,
	};
	int pc;

	if (flen == 0 || flen > BPF_MAXINSNS)
		die("chk_filter");

	/* check the filter code now */
	for (pc = 0; pc < flen; pc++) {
		struct sock_filter *ftest = &filter[pc];
		u16 code = ftest->code;

		if (code >= N(codes))
			die("chk_filter");
		printf("pc=%d: codes[%d] -> %d\n", pc, code, codes[code]);
		code = codes[code];
		if (!code)
			die("chk_filter");
		/* Some instructions need special checks */
		switch (code) {
		case BPF_S_ALU_DIV_K:
			/* check for division by zero */
			if (ftest->k == 0)
				die("chk_filter");
//			ftest->k = reciprocal_value(ftest->k); // disabled
			break;
		case BPF_S_LD_MEM:
		case BPF_S_LDX_MEM:
		case BPF_S_ST:
		case BPF_S_STX:
			/* check for invalid memory addresses */
			if (ftest->k >= BPF_MEMWORDS)
				die("chk_filter");
			break;
		case BPF_S_JMP_JA:
			/*
			 * Note, the large ftest->k might cause loops.
			 * Compare this with conditional jumps below,
			 * where offsets are limited. --ANK (981016)
			 */
			if (ftest->k >= (unsigned)(flen-pc-1))
				die("chk_filter");
			break;
		case BPF_S_JMP_JEQ_K:
		case BPF_S_JMP_JEQ_X:
		case BPF_S_JMP_JGE_K:
		case BPF_S_JMP_JGE_X:
		case BPF_S_JMP_JGT_K:
		case BPF_S_JMP_JGT_X:
		case BPF_S_JMP_JSET_X:
		case BPF_S_JMP_JSET_K:
			/* for conditionals both must be safe */
			if (pc + ftest->jt + 1 >= flen ||
			    pc + ftest->jf + 1 >= flen)
				die("chk_filter: die if %d >= %d || %d >= %d",
					pc + ftest->jt + 1, flen,
					pc + ftest->jf + 1, flen
				);
			break;
		case BPF_S_LD_W_ABS:
		case BPF_S_LD_H_ABS:
		case BPF_S_LD_B_ABS:
#define ANCILLARY(CODE) case SKF_AD_OFF + SKF_AD_##CODE:	\
				code = BPF_S_ANC_##CODE;	\
				break
			switch (ftest->k) {
			ANCILLARY(PROTOCOL);
			ANCILLARY(PKTTYPE);
			ANCILLARY(IFINDEX);
			ANCILLARY(NLATTR);
			ANCILLARY(NLATTR_NEST);
			ANCILLARY(MARK);
			ANCILLARY(QUEUE);
			ANCILLARY(HATYPE);
			ANCILLARY(RXHASH);
			ANCILLARY(CPU);
			}
		}
		//ftest->code = code;
	}

	/* last instruction must be a RET code */
	switch (filter[flen - 1].code) {
	case BPF_RET|BPF_K:
	case BPF_RET|BPF_A:
		return check_load_and_stores(filter, flen);
	}
	die("chk_filter");
}
#endif
/************************ BPF check code from the Linux kernel */
