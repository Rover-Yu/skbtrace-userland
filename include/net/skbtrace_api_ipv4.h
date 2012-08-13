/*
 *  skbtrace - sk_buff trace utilty
 *
 *	User/Kernel Interface
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
#ifndef _NET_SKBTRACE_API_IPV4_H
#define _NET_SKBTRACE_API_IPV4_H

#include <linux/types.h>

#ifdef __KERNEL__
#include <linux/in.h>
#include <linux/in6.h>
#endif

/********************* TCP section *********************/

/* skbtrace_block->action */
enum {
	skbtrace_action_tcp_min		= 101,
	skbtrace_action_tcp_congestion	= 101,
	skbtrace_action_tcp_connection	= 102,
	skbtrace_action_tcp_sendlimit	= 103,
	skbtrace_action_tcp_active_conn	= 104,
	skbtrace_action_tcp_rttm	= 105,
	skbtrace_action_tcp_ca_state	= 106,
	skbtrace_action_tcp_max		= 199,
};

/* TCP congestion event (101) */

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
	__u32	rto;
	__u32	cwnd;
	__u32	sndnxt;
	__u32	snduna;
} __packed;

/* TCP basic connection events */
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

/* TCP send limit event */
enum {
	skbtrace_tcp_sndlim_cwnd	= 4,
	skbtrace_tcp_sndlim_swnd	= 5,
	skbtrace_tcp_sndlim_nagle	= 6,
	skbtrace_tcp_sndlim_tso		= 7,
	skbtrace_tcp_sndlim_frag	= 8,	/* most likely ENOMEM errors */
	skbtrace_tcp_sndlim_pushone	= 9,
	skbtrace_tcp_sndlim_other	= 10,
	skbtrace_tcp_sndlim_ok		= 11,
};


/* val member:
 *    skbtrace_tcp_sndlim_other: the return value of tcp_transmit_skb()
 *    skbtrace_tcp_sndlim_ok: total sent pkts
 *    other cases: send limit occurs under MTU probe if 1, otherwise, it is 0
 */
struct skbtrace_tcp_sendlim_blk {
	struct skbtrace_block blk;
	__u32 val;
	__u32 count;
	struct timespec begin;
	__u32	snd_ssthresh;
	__u32	snd_cwnd;
	__u32	snd_cwnd_cnt;
	__u32	snd_wnd;
} __packed;

/* TCP active connections */
/* Use skbtrace_tcp_conn_blk */

/* TCP RTTM */
struct skbtrace_tcp_rttm_blk {
	struct skbtrace_block blk;
	__u32 pad;
	__u32 snd_una;
	__u32 rtt_seq;
	__u32 rtt;
	__u32 rttvar;
	__u32 srtt;
	__u32 mdev;
	__u32 mdev_max;
} __packed;

/* TCP CA state */
struct skbtrace_tcp_ca_state_blk {
	struct skbtrace_block blk;

        __u32	cwnd;
        __u32	rto;
        __u32	snduna;
        __u32	sndnxt;

        __u32	snd_ssthresh;
        __u32	snd_wnd;
        __u32	rcv_wnd;
        __u32	high_seq;

        __u32	packets_out;
        __u32	lost_out;
        __u32	retrans_out;
        __u32	sacked_out;

        __u32	fackets_out;
        __u32	prior_ssthresh;
        __u32	undo_marker;
        __u32	undo_retrans;

        __u32	total_retrans;
        __u32	reordering;
        __u32	prior_cwnd;
        __u32	mss_cache;

} __packed;

/* TCP timer flags */
enum {
	skbtrace_tcp_timer_rexmit = skbtrace_sk_timer_last + 1,
	skbtrace_tcp_timer_probe,
	skbtrace_tcp_timer_keepalive,
	skbtrace_tcp_timer_delack,
};

/********************* icsk section *********************/

/* skbtrace_block->action */
enum {
	skbtrace_action_icsk_min	= 201,
	skbtrace_action_icsk_connection	= 201,
	skbtrace_action_icsk_max	= 299,
};

/* Use skbtrace_tcp_active_conn */

#endif
