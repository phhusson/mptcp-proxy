#!/bin/sh

all: mpproxy mptcp_proxy

mpproxy: mpproxy.o
	gcc -g -o mpproxy mpproxy.o 

mptcp_proxy: mptcp_proxy.o mangleman.o conman.o sessman.o sflman.o packman.o mptcpproxy_util.o map_table.o tp_heap.o hmac_sha1.o sha1.o -lnetfilter_queue
	gcc -g -o mptcp_proxy mptcp_proxy.o mangleman.o conman.o sessman.o sflman.o packman.o mptcpproxy_util.o map_table.o tp_heap.o hmac_sha1.o sha1.o -lnetfilter_queue -lnfnetlink

mpproxy.o: mpproxy.c
	gcc -c mpproxy.c

mptcp_proxy.o: mptcp_proxy.c mptcpproxy_util.h mptcp_proxy.h sflman.h sessman.h packman.h conman.h mangleman.h
	gcc -c mptcp_proxy.c

mangleman.o: mangleman.c  mangleman.h map_table.h mptcpproxy_util.h sflman.h sessman.h packman.h conman.h
	gcc -c mangleman.c

conman.o: conman.c conman.h mptcpproxy_util.h mangleman.h sflman.h sessman.h packman.h
	gcc -c conman.c

sessman.o: sessman.c sessman.h mptcpproxy_util.h tp_heap.h map_table.h sflman.h packman.h conman.h
	gcc -c sessman.c

sflman.o: sflman.c sflman.h mptcpproxy_util.h tp_heap.h map_table.h  sessman.h packman.h conman.h
	gcc -c sflman.c

packman.o: packman.c packman.h mptcpproxy_util.h sflman.h sessman.h packman.h conman.h
	gcc -c packman.c

map_table.o: map_table.c mptcpproxy_util.h map_table.h 
	gcc -c map_table.c

mptcpproxy_util.o: mptcpproxy_util.c tp_heap.h sha1.h mptcpproxy_util.h 
	gcc -c mptcpproxy_util.c

tp_heap.o: tp_heap.c tp_heap.h
	gcc -c tp_heap.c

hmac_sha1.o: hmac_sha1.c sha1.h hmac.h
	gcc -c hmac_sha1.c

sha1.o: sha1.c sha1.h
	gcc -c sha1.c

install: mpproxy mptcp_proxy
	cp mpproxy /usr/bin
	cp mptcp_proxy /usr/bin


