#! /usr/bin/python

import struct
import socket
from util import *

class skb_rps_info:
	action = 1
	def __init__(self, block, trace):
		self.blk = block
		size = block.len - block.common_header_size()
		data = trace.read(size)
		if not data:
			raise ValueError, "invalid skb_rps_info block"
		queue_fmt = "Hxx"
		rest_fmt = "IIIIIHHI"
		self.rx_queue = struct.unpack(queue_fmt, data[0:4])
		self.rx_hash, self.cpu, self.ifindex, self.src, self.dst, \
			self.sport, self.dport, self.proto = struct.unpack(rest_fmt, data[4:])

	def __str__(self):
		s = ["action=skb_rps_info"]
		s += [" skb=0x%x" % self.blk.ptr]
		s += [" rx-queue=%d" % self.rx_queue]
		s += [" rx-hash=0x%x" % self.rx_hash]
		s += [" cpu=0x%x" % self.cpu]
		s += [" ifindex=%d" % self.ifindex]
		s += [" src=%x" % self.src]
		s += [" dst=%x" % self.dst]
		s += [" sport=%d" % socket.ntohs(self.sport)]
		s += [" dport=%d" % socket.ntohs(self.dport)]
		s += [" proto=0x%x" % self.proto]
		return "".join(s)

class skb_delay:
	action = 3
	def __init__(self, block, trace):
		self.blk = block
		size = block.len - block.common_header_size()
		data = trace.read(size)
		if not data:
			raise ValueError, "invalid skb_delay block"
		fmt = "LLLL"
		self.sk, self.loc, self.start_sec, self.start_usec = \
					struct.unpack(fmt, data[:32])
		data = data[32:]

		slot_fmt = "LL"
		nr_slots = (size - 32) / 16
		self.slots = []
		for slot in range(nr_slots):
			slot_data = data[slot * 16 : slot * 16 + 16]
			loc, usec = struct.unpack(slot_fmt, slot_data)
			self.slots.append((loc, usec))

	def __str__(self):
		s = ["action=skb_delay"]
		flags = ""
		if self.blk.flags & 0x1:
			flags += "overflow"
		if self.blk.flags & 0x2:
			flags += ",error"
		if flags:
			s += [" flags=" + flags]
		s += [" skb=0x%x" % self.blk.ptr]
		s += [" sock=0x%x" % self.sk]
		s += [" start_loc=%s" % kallsyms_lookup(self.loc)]
#		s += [" start_ts=%d.%ds" % (self.start_sec, self.start_usec)]
		if self.slots:
			s += [ " history=[" ]
		for slot in self.slots:
			s += "(%s,%d) " % (kallsyms_lookup(slot[0]), slot[1])
		if self.slots:
			s += ["]"]
		return "".join(s)

events_list = [skb_rps_info, skb_delay]
