#! /usr/bin/python

import struct
import socket

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

events_list = [skb_rps_info]
