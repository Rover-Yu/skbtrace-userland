#! /usr/bin/python

import struct
from util import *

class tcp_cong:
	flags = {
		1<<4 :	"CWR",
		1<<5 :	"Loss",	
		1<<6 :	"FastRtx",
		1<<7 :	"FRTO",
		1<<8 :	"FRTO-Loss",
		1<<9 :	"Leave",
	}
	action = 101
	def __init__(self, block, trace):
		self.blk = block
		size = block.len - block.common_header_size()
		self.state = tcp_cong.flags[self.blk.flags]
		data = trace.read(size)
		if not data:
			raise ValueError, "invalid tcp_cong block"
		fmt = "IIIII"
		self.rcv_rtt, self.rto, self.cwnd, self.sndnxt, self.snduna = struct.unpack(fmt, data)

	def __str__(self):
		s = "action=tcp_cong"
		s += " sk=0x%x" % self.blk.ptr
		s += " cwnd=%d" % self.cwnd
		s += " rto=%d" % self.rto
		s += " rcv_rtt=%d" % self.rcv_rtt
		s += " sndnxt=%d" % self.sndnxt
		s += " snduna=%d" % self.snduna
		return s

class tcp_conn:
	flags = {
		1<<4  : "ESTABLISHED",
		1<<5  : "SYN_SENT",
		1<<6  : "SYN_RECV",
		1<<7  : "FIN_WAIT1",
		1<<8  : "FIN_WAIT2",
		1<<9  : "TIME_WAIT",
		1<<10 : "CLOSE",
		1<<11 : "CLOSE_WAIT",
		1<<12 : "LAST_ACK",
		1<<13 : "LISTEN",
		1<<14 : "CLOSING",
	}
	action = 102
	def __init__(self, block, trace):
		self.blk = block
		size = block.len - block.common_header_size()
		self.state = tcp_conn.flags.get(self.blk.flags, self.blk.flags)
		data = trace.read(size)
		if not data:
			raise ValueError, "invalid tcp_conn block"
		self.local = None
		self.peer = None
		local, size = parse_sockaddr(data)
		if size:
			self.local = local
		if not (block.flags & ((1<<8)|(1<<9))):
			peer, size = parse_sockaddr(data[size:])
			if size:
				self.peer = peer

	def __str__(self):
		s = "action=tcp_conn"
		s += " sk=0x%x " % self.blk.ptr
		s += " state=%s" % self.state
		if self.local:
			s += " local=%s:%d" % self.local
		if self.peer:
			s += " peer=%s:%d" % self.peer
		return s

class tcp_sendlim:
	flags = {
		1<<4 :     "cwnd",
		1<<5 :     "swnd",
		1<<6 :     "nagle",
		1<<7 :     "tso",
		1<<8 :     "frag",
		1<<9 :     "pushone",
		1<<10 :    "other",
		1<<11 :    "ok",
	}
	action = 103
	def __init__(self, block, trace):
		self.blk = block
		size = block.len - block.common_header_size()
		self.reason = tcp_sendlim.flags[self.blk.flags]
		data = trace.read(size)
		if not data:
			raise ValueError, "invalid tcp_sendlim block"
		fmt = "IILLIIII"
		self.val, self.cnt, self.sec, self.nsec, self.ssthresh, \
			self.cwnd, self.cwnd_cnt, self.swnd = struct.unpack(fmt, data)

	def __str__(self):
		s = "action=tcp_sendlim"
		s += " sk=0x%x" % self.blk.ptr
		s += " begin=%d.%d" % (self.sec, self.nsec)
		s += " cnt=%d" % self.cnt
		if (1<<11) & self.blk.flags: #OK
			s += " sentpkts=%d" % self.val
		elif (1<<10) & self.blk.flags: # other
			s += " errcode=%d" % self.val
		else:
			s += " mtuprobe=%d" % self.val
		s += " ssthresh=%d cwnd=%d/%d swnd=%d" % \
			(self.ssthresh, self.cwnd, self.cwnd_cnt, self.swnd)
		return s

class icsk_conn:
	action = 201
	def __init__(self, block, trace):
		self.blk = block
		size = block.len - block.common_header_size()
		data = trace.read(size)
		if not data:
			raise ValueError, "invalid icsk_conn block"
		self.local = None
		local, size = parse_sockaddr(data)
		if size:
			self.local = local

	def __str__(self):
		s = "action=icsk_conn"
		s  = " sk=0x%x" % self.blk.ptr
		s  = " state=LISTEN"
		if self.local:
			s += " local=%s:%d" % (self.local[0], self.local[1])
		return s

class tcp_conn_addr:
	action = 104
	def __init__(self, block, trace):
		self.blk = block
		size = block.len - block.common_header_size()
		data = trace.read(size)
		if not data:
			raise ValueError, "invalid tcp_conn_addr block"
		self.local = None
		self.peer = None
		local, size = parse_sockaddr(data)
		if not size:
			self.local = local
		if (block.flags & ((1<<8)|(1<<9))):
			self.peer = None
		else:
			peer, size = parse_sockaddr(data[size:])
			if size:
				self.peer = peer

	def __str__(self):
		s = "action=tcp_conn_addr"
		s += " sk=0x%x" % self.blk.ptr
		s += " state=ESTABLISHED"
		if self.local:
			s += " local=%s:%d" % (self.local[0], self.local[1])
		if self.peer:
			s += " peer=%s:%d" % (self.peer[0], self.peer[1])
		return s

class tcp_rttm:
	action = 105
	def __init__(self, block, trace):
		self.blk = block
		size = block.len - block.common_header_size()
		data = trace.read(size)
		if not data:
			raise ValueError, "invalid tcp_rttm block"
		fmt = "IIIIIII"
		self.snd_una, self.rtt_seq, self.rtt, self.rttvar,\
			self.srtt, self.mdev, self.mdev_max = \
						struct.unpack(fmt, data)

	def __str__(self):
		s = "action=tcp_rttm"
		s += " sk=0x%x" % self.blk.ptr
		s += " snd_una=%d" % self.snd_una
		s += " rtt_seq=%d" % self.rtt_seq
		s += " rtt=%d" % self.rtt
		s += " rttvar=%d" % self.rttvar
		s += " srtt=%d" % self.srtt
		s += " mdev=%d" % self.mdev
		s += " mdev_max=%d" % self.mdev_max
		return s


events_list = [tcp_cong, tcp_conn, tcp_sendlim,\
		icsk_conn, tcp_conn_addr, tcp_rttm]
