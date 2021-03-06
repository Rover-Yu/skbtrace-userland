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
#ifndef _NET_SKBTRACE_API_COMMON_H
#define _NET_SKBTRACE_API_COMMON_H

#include <linux/types.h>

/********************* Common section *********************/

/* skbtrace_block->action */
enum {
	skbtrace_action_invalid		= 0,
	skbtrace_action_common_min	= 1,
	skbtrace_action_skb_rps_info	= 1,
	skbtrace_action_sk_timer	= 2,
	skbtrace_action_common_max	= 99,
};

/* common skbtrace_block->flags */
enum {
	skbtrace_flags_reserved_min = 0,
	skbtrace_flags_reserved_0 = 0,
	skbtrace_flags_reserved_1 = 1,
	skbtrace_flags_reserved_2 = 2,
	skbtrace_flags_reserved_3 = 3,
	skbtrace_flags_reserved_max = 3,
};

/* it is copied from <net/flow_keys.h>, except pad fields and packed */
struct skbtrace_flow_keys {
	__u32 src;
	__u32 dst;
	union {
		__u32 ports;
		__u16 port16[2];
	};
	__u32 ip_proto;
} __packed;

struct skbtrace_skb_rps_info_blk {
	struct skbtrace_block blk;
	__u16 rx_queue;
	__u16 pad;
	__u32 rx_hash;
	__u32 cpu;
	__u32 ifindex;
	struct skbtrace_flow_keys keys;
} __packed;


/* socket timers */
/* flags */
enum {
	skbtrace_sk_timer_setup	= 4,
	skbtrace_sk_timer_reset	= 5,
	skbtrace_sk_timer_stop	= 6,
	skbtrace_sk_timer_last	= 6,
};

struct skbtrace_sk_timer_blk {
	struct skbtrace_block blk;
	__s32	proto;
	__s32	timeout;
} __packed;

#endif
