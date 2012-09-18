CC	= gcc
CFLAGS	= -Wall -g -W -I./include
ALL_CFLAGS = $(CFLAGS) -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PROGS	= skbtrace
LIBS	= -lpthread -lpcap
ALL = $(PROGS)

#SSH_TARGET = 192.168.43.133
#SSH_TARGET=10.32.228.103
SSH_TARGET=10.32.6.189
#USER=root
USER=sailor

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
	scp ../skbtrace-userland/*.[ch] ${USER}@${SSH_TARGET}:/tmp/userland
	scp ../skbtrace-userland/Makefile ${USER}@${SSH_TARGET}:/tmp/userland
	scp ../skbtrace-userland/skbparse ${USER}@${SSH_TARGET}:/tmp/userland
	scp ../skbtrace-userland/*.py ${USER}@${SSH_TARGET}:/tmp/userland
	scp -r ../skbtrace-userland/include ${USER}@${SSH_TARGET}:/tmp/userland

scpfrom:
	scp ${USER}@${SSH_TARGET}:/tmp/userland/*.c .
	scp ${USER}@${SSH_TARGET}:/tmp/userland/skbparse .
	scp ${USER}@${SSH_TARGET}:/tmp/userland/*.py .

clean: 
	rm -f *.o $(PROGS) tags cscope*
