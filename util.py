#! /usr/bin/python

import socket
import sys

SZ_SOCKADDR_IN4 = 16
SZ_SOCKADDR_IN6 = 28

SZ_ADDR_IN4 = 4
SZ_ADDR_IN6 = 16

def parse_sockaddr(sockaddr):
	family = sockaddr[:2]
	family = (ord(family[1]) << 8) + ord(family[0])
	if family == socket.AF_INET:
		sin_port = sockaddr[2:2+2]
		port = (ord(sin_port[0]) << 8) + ord(sin_port[1])
		sin_addr = sockaddr[4:4+SZ_ADDR_IN4]
		addr = socket.inet_ntop(socket.AF_INET, sin_addr)
		sz = SZ_SOCKADDR_IN4
	elif family == socket.AF_INET6:
		sin6_port = sockaddr[2:2+2]
		port = (ord(sin6_port[0]) << 8) + ord(sin6_port[1])
		sin6_addr = sockaddr[8:8+SZ_ADDR_IN6]
		addr = socket.inet_ntop(socket.AF_INET6, sin6_addr)
		sz = SZ_SOCKADDR_IN6
	else:
		return ("family-%d-addr" % family, 0), 0
	return (addr, port), sz

channel_table = {
	0 : "syscall",
	1 : "softirq",
	2 : "hardirq",
}

def open_file(fn, mode):
	try:
		return file(fn, mode)
	except IOError, OSError:
		print "Can't open", fn
		sys.exit(1)

