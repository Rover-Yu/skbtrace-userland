CC	= gcc
CFLAGS	= -Wall -g -W -I./include
ALL_CFLAGS = $(CFLAGS) -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PROGS	= skbtrace
LIBS	= -lpthread -lpcap
#SSH_TARGET = 192.168.43.133
#SSH_TARGET=10.32.228.103
SSH_TARGET=10.32.6.189
ALL = $(PROGS)

all: $(ALL)

index:
	@cscope -b -q -R
	@ctags -R

%.o: %.c
	$(CC) -o $*.o -c $(ALL_CFLAGS) $<

skbtrace: skbtrace.o
	$(CC) $(ALL_CFLAGS) -o $@ $(filter %.o,$^) $(LIBS)

scp:
	ssh root@${SSH_TARGET} mkdir -p /tmp/userland
	scp ../skbtrace-userland/*.[ch] root@${SSH_TARGET}:/tmp/userland
	scp ../skbtrace-userland/Makefile root@${SSH_TARGET}:/tmp/userland
	scp ../skbtrace-userland/skbparse* root@${SSH_TARGET}:/tmp/userland
	scp ../skbtrace-userland/*.py root@${SSH_TARGET}:/tmp/userland
	scp -r ../skbtrace-userland/include root@${SSH_TARGET}:/tmp/userland

scpfrom:
	scp root@${SSH_TARGET}:/tmp/userland/*.c .
	scp root@${SSH_TARGET}:/tmp/userland/skbparse* .
	scp root@${SSH_TARGET}:/tmp/userland/*.py .

clean: 
	rm -f *.o $(PROGS) tags cscope*
