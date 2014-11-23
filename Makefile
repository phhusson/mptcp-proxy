CC?=gcc
CFLAGS?=-Wall -Wextra -O2 -g -std=gnu11 -fno-strict-aliasing
LDLIBS=-lnetfilter_queue -lnfnetlink

all: mpproxy mptcp_proxy

mpproxy: mpproxy.o

mptcp_proxy: mptcp_proxy.o mangleman.o conman.o sessman.o sflman.o packman.o mptcpproxy_util.o map_table.o tp_heap.o hmac_sha1.o sha1.o

mptcp_proxy.o: mptcp_proxy.c mptcpproxy_util.h mptcp_proxy.h sflman.h sessman.h packman.h conman.h mangleman.h

mangleman.o: mangleman.c  mangleman.h map_table.h mptcpproxy_util.h sflman.h sessman.h packman.h conman.h

conman.o: conman.c conman.h mptcpproxy_util.h mangleman.h sflman.h sessman.h packman.h

sessman.o: sessman.c sessman.h mptcpproxy_util.h tp_heap.h map_table.h sflman.h packman.h conman.h

sflman.o: sflman.c sflman.h mptcpproxy_util.h tp_heap.h map_table.h  sessman.h packman.h conman.h

packman.o: packman.c packman.h mptcpproxy_util.h sflman.h sessman.h packman.h conman.h

map_table.o: map_table.c mptcpproxy_util.h map_table.h 

mptcpproxy_util.o: mptcpproxy_util.c tp_heap.h sha1.h mptcpproxy_util.h 

tp_heap.o: tp_heap.c tp_heap.h

hmac_sha1.o: hmac_sha1.c sha1.h hmac.h

sha1.o: sha1.c sha1.h

install: mpproxy mptcp_proxy
	cp mpproxy /usr/bin
	cp mptcp_proxy /usr/bin

clean:
	rm -f *.o mpproxy mptcp_proxy
