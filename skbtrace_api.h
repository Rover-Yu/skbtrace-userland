/*
 *  skbtrace - sk_buff trace utilty
 *
 * 	User/Kernel Interface
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * 2012 Li Yu <bingtian.ly@taobao.com>
 *
 */
#ifndef _LINUX_SKBTRACE_API_H
#define _LINUX_SKBTRACE_API_H

#include <asm/types.h>

#ifdef __KERNEL__
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/in6.h>
#else
#include <time.h>
#define TASK_COMM_LEN	16
#define __packed	__attribute__ ((__packed__))
#endif

#define TRACE_NAME_MAX_LEN	256
#define FILTER_NAME_MAX_LEN	256

#define SKBTRACE_DEF_SUBBUF_SIZE	(1<<7)
#define SKBTRACE_DEF_SUBBUF_NR	(1<<11)

#define SKBTRACE_MIN_SUBBUF_SIZE	SKBTRACE_DEF_SUBBUF_SIZE
#define SKBTRACE_MIN_SUBBUF_NR		SKBTRACE_DEF_SUBBUF_NR

#define SKBTRACE_MAX_SUBBUF_SIZE	(1<<12)
#define SKBTRACE_MAX_SUBBUF_NR		(1<<20)

#define SC	0	/* for tracepoints in othersides, e.g. syscall */
#define SI	1	/* for tracepoints in softirq */
#define HW	2	/* for tracepoints in hardware IRQ */
#define NR_CHANNELS	3

/********************* Common section *********************/

/* skbtrace_block->action */
enum {
	skbtrace_action_common_min	= 1,
	skbtrace_action_context		= 1,
	skbtrace_action_drop		= 2,
	skbtrace_action_common_max	= 99,

};

/* common skbtrace_block->flags */
enum {
	skbtrace_flags_reserved_min = 3,
	skbtrace_flags_reserved_0 = 0,
	skbtrace_flags_reserved_1 = 1,
	skbtrace_flags_reserved_2 = 2,
	skbtrace_flags_reserved_3 = 3,
	skbtrace_flags_reserved_max = 3,
};

/* skbtrace_block->flags for skb_context */
enum {
	skbtrace_context_tx = 4,	/* outbound or inbound */
};

/* struct skbtrace_block - be used in kernel/user interaction */
/* @len:	whole data structure size in bytes */
/* @action:	action of this skbtrace_block */
/* @flags:	the flags depend on above action field */
/* @ts:		the timestamp of this event. */
/* @ptr:	the major source kernel data structure of this event, for gerneral, a sk_buff or sock */
struct skbtrace_block {
	__u16 len;
	__u16 action;
	__u32 flags;
	struct timespec ts;
	u64 seq;
	void *ptr;
} __packed;

#define SKBTRACE_DROP_DESC_SZ	16
struct skbtrace_drop_blk {
	struct skbtrace_block blk;
	void *ip;
	char desc[SKBTRACE_DROP_DESC_SZ];
} __packed;

struct skbtrace_context_blk {
	struct skbtrace_block blk;
	pid_t pid;	/* FIXME: namespace support */
	pid_t tid;
	void *sk;
	char comm[TASK_COMM_LEN];
} __packed;

/********************* TCP section *********************/

/* skbtrace_block->action */
enum {
	skbtrace_action_tcp_min		= 101,
	skbtrace_action_tcp_congnestion = 101,
	skbtrace_action_tcp_connection	= 102,
	skbtrace_action_tcp_sendlimit	= 103,
	skbtrace_action_tcp_max		= 199,
};

/* TCP congestion event (100) */

/* flags */
enum {
	skbtrace_tcp_cong_cwr		= 4,
	skbtrace_tcp_cong_loss		= 5,
	skbtrace_tcp_cong_fastrtx	= 6,
	skbtrace_tcp_cong_frto		= 7,
	skbtrace_tcp_cong_frto_loss	= 8,
	skbtrace_tcp_cong_leave		= 9,
};

struct skbtrace_tcp_cong_blk {
	struct skbtrace_block blk;
	__u32	srtt;
	__u32	rto;
	__u32	cwnd;
	__u32	sndnxt;
	__u32	snduna;
} __packed;

/* TCP basic connection events (101) */
struct skbtrace_tcp_conn_blk {
	struct skbtrace_block blk;
	union {
		struct {
			struct sockaddr local;
			struct sockaddr peer;
		};
		struct {
			struct sockaddr_in local;
			struct sockaddr_in peer;
		} inet;
		struct {
			struct sockaddr_in6 local;
			struct sockaddr_in6 peer;
		} inet6;
	} addr;
} __packed;

/* TCP send limit event (102) */
enum {
	skbtrace_tcp_sndlim_cwnd	= 4,
	skbtrace_tcp_sndlim_swnd	= 5,
	skbtrace_tcp_sndlim_nagle	= 6,
	skbtrace_tcp_sndlim_tso		= 7,
	skbtrace_tcp_sndlim_frag	= 8,	/* most likely ENOMEM errors */
	skbtrace_tcp_sndlim_other	= 9,
};

struct skbtrace_tcp_sendlim_blk {
	struct skbtrace_block blk;
	int val;	/* the return value of tcp_transmit_skb() */
	int count;
	struct timespec begin;
} __packed;

#endif
