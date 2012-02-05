CC	= gcc
CFLAGS	= -Wall -g -W
ALL_CFLAGS = $(CFLAGS) -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PROGS	= skbtrace
LIBS	= -lpthread
SSH_TARGET = 172.16.227.128
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
	scp ../skbtrace-userland/* root@${SSH_TARGET}:/tmp/userland

scpfrom:
	scp root@${SSH_TARGET}:/tmp/userland/* .

clean: 
	rm -f *.o $(PROGS) tags cscope*
