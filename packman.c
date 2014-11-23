//*****************************************************
//*****************************************************
//
// packman.c 
// Project: mptcp_proxy
//
//*****************************************************
//*****************************************************
//
// GEORG HAMPEL - Bell Labs/NJ/USA: All Rights Reserved
//
//*****************************************************
//*****************************************************
//***************************************************** 

#include "mptcpproxy_util.h"
#include "packman.h"
#include "sflman.h"
#include "sessman.h"
#include "conman.h"

struct mptcp_option mptopt[10];
struct tcp_option topt[20];


//++++++++++++++++++++++++++++++++++++++++++++++++
//Filter: create_packet(..)
//	packet written to buf
//	returns *plen 
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_packet(unsigned char *buf, uint16_t *plen, 
	struct fourtuple *pft, 
	uint32_t sn, //netork format
	uint32_t an, //netork format
	unsigned char flags,//network format 
	uint16_t win, //network format
	unsigned char *buf_opt, 
	uint16_t len_opt) {

	len_opt=pad_options_buffer(buf_opt, len_opt);	

	uint16_t iplen = 20;
	uint16_t tcplen = 20;
	unsigned char offset = tcplen+len_opt;
	*plen = iplen+offset;
	memset(buf, 0, *plen);


	//enter options 
	memcpy(buf+iplen+tcplen, buf_opt, len_opt);

	//tcp header
	*((uint16_t*)(buf + iplen)) = htons(pft->prt_loc);
	*((uint16_t*)(buf+ iplen+2)) = htons(pft->prt_rem);
	*((uint32_t*)(buf+ iplen+4)) = sn;	
	*((uint32_t*)(buf+ iplen+8)) = an;
	*(buf+ iplen+13) = flags;
	*((uint16_t*)(buf+ iplen+14)) = win;
	*(buf+ iplen+12) = (unsigned char) (offset<<2);//divided by 2 and leftshift4


	//IP header
	*buf = 69;//version 4 ^^4 + 5
	*(buf+6) = 0x40;
	*(buf+8) = 64;//TTL
	*(buf+9) = 6;//TCP
	*((uint16_t*)(buf+2)) = htons(*plen);
	*((uint32_t*)(buf+12)) = htonl(pft->ip_loc);	
	*((uint32_t*)(buf+16)) = htonl(pft->ip_rem);

	//update of both checksums
	compute_checksums(buf, iplen, *plen);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//send_raw_packet 
//ip_dst, prt_dst in network format
//++++++++++++++++++++++++++++++++++++++++++++++++
int send_raw_packet(size_t sd, unsigned char *buf, uint16_t len, uint32_t ip_dst) {
	//send packet on raw socket
	struct sockaddr_in sin;	
	sin.sin_family = AF_INET;
	sin.sin_port = ip_dst;
	sin.sin_addr.s_addr = ip_dst;
	
	int ret = sendto(sd, buf, len,0,(struct sockaddr*) &sin, sizeof(sin));
	
	return ret;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: send_reset_fourtuple()
// Sends sest on a certain fourtuple
//++++++++++++++++++++++++++++++++++++++++++++++++
int send_reset_fourtuple(struct fourtuple *ft, uint32_t seq_nb) {
	//create ACK packet
	//char opt_buf[opt_len];
	uint16_t pack_len;

	//append mptcp_opt_buf to packd.tcp_opt_buf; packd.tcp_opt_len is extended
	unsigned char mptcp_opt_buf[4];
	create_dummy_dssopt(mptcp_opt_buf);

	create_packet(raw_buf, &pack_len, 
		ft,
		htonl(seq_nb), 
		0,
		4,//RST (4) 
		0,//window setting 
		mptcp_opt_buf, 
		4);//opt len

	//send packet
	if(send_raw_packet(raw_sd, raw_buf,  pack_len, htonl(ft->ip_rem))<0)
		return 0;

	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: cache_packet_header: Buffers signaling packet header for retransmission purposes
//++++++++++++++++++++++++++++++++++++++++++++++++
void cache_packet_header(){
	if(packd.tcplen + packd.ip4len > 120)
		return;

	memcpy(packd.sess->rex_buf, packd.new_buf, packd.tcplen + packd.ip4len);
	packd.sess->rex_buf_len = packd.tcplen + packd.ip4len;
	packd.sess->rex_ip4_len = packd.ip4len;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//copy_cached_packet:
//   Copies packet buffered in session to new_buf
//++++++++++++++++++++++++++++++++++++++++++++++++
void retransmit_cached_packet_header() {
	//add ipv4 header, core tcp header
	memmove(packd.new_buf, packd.sess->rex_buf, packd.sess->rex_buf_len);

	//copy payload of packet, if there is
	if(packd.paylen > 0)
		memmove(packd.new_buf + packd.sess->rex_buf_len, packd.buf + packd.ip4len + packd.tcplen, packd.paylen);

	//update packd
	packd.ip4len = packd.sess->rex_ip4_len;
	packd.tcplen = packd.sess->rex_buf_len - packd.sess->rex_ip4_len;
	packd.totlen = packd.sess->rex_buf_len + packd.paylen;

	packd.pos_thead = packd.pos_i4head + packd.ip4len;
	packd.pos_pay = packd.pos_i4head + packd.ip4len + packd.tcplen; 

	packd.ip4h = (struct ipheader*) (packd.new_buf+packd.pos_i4head);
	packd.tcph = (struct tcpheader*) (packd.new_buf+packd.pos_i4head+packd.ip4len);

	//add new tcp header length into packet
	packd.tcph->th_off = packd.tcplen>>2;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//int parse_compact_copy_TCP_options(unsigned char *tcp_opt, uint16_t len)
//	bundle a bunch of functions
//++++++++++++++++++++++++++++++++++++++++++++++++
void parse_compact_copy_TCP_options(unsigned char *tcp_opt, uint16_t len) {
	//parse and compact options into topt
	size_t nb_tcp_options = parse_compact_options(tcp_opt, len, topt);

	//copy all parsed options (topt) to packd.tcp_opt_buf
	packd.tcp_opt_len = copy_options_to_buffer(packd.tcp_opt_buf, nb_tcp_options, topt);

	packd.tcp_options_compacted = 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//append_TCP_option
//	topt is the new option and len its length
//	topt is attached to the options in packet after compacting them
//	If header to long, returns 0 without doing anything, otherwise 1
//++++++++++++++++++++++++++++++++++++++++++++++++
int append_TCP_option(unsigned char *tcp_opt, uint16_t *plen, unsigned char *new_tcp_opt, uint16_t new_len) {
	if(*plen + new_len > 40) return 0;

	//append new option to tcp_opt_buf
	memmove(tcp_opt + *plen, new_tcp_opt, new_len);
	*plen += new_len;

	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPCAP option
//	mpbuf points to packd.tptop_opt_buf.
//	For SYN and SYN/ACK, only key_loc is provided. 
//	For final ACK both keys are provided
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_MPcap(unsigned char *mpbuf, uint32_t *key_loc, uint32_t *key_rem) {
	unsigned char tpcap_len = (key_rem == NULL)? 12:20;
	if(packd.mptcp_opt_len + tpcap_len > 40) return 0;

	packd.mptcp_opt_len += tpcap_len;
	*(mpbuf) = MPTCP_KIND;
	*(mpbuf+1) = tpcap_len;
	*(mpbuf+2) = ( ((unsigned char) MPTCP_CAP)<<4) & 0xf0;
	*(mpbuf+3) = 1;//no checksum
	*((uint32_t*) (mpbuf+4)) = key_loc[0];
	*((uint32_t*) (mpbuf+8)) = key_loc[1];
	if(key_rem != NULL) {
		*((uint32_t*) (mpbuf+12)) = key_rem[0];//only used for ACK
		*((uint32_t*) (mpbuf+16)) = key_rem[1];//only used for ACK
	}
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//create_dummy_dssopt(..)
//	creates mpbuf for dummy DSS
//      used when terminating subflows
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_dummy_dssopt(unsigned char *mpbuf){
	*(mpbuf) = MPTCP_KIND;
	*(mpbuf+1) = 4;
	*(mpbuf+2) = ( ((unsigned char) MPTCP_DSS)<<4) & 0xf0;
	*(mpbuf+3) = 0;
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPJOIN option: SYN
//	top points to the beginning of the TCP options
//	len provides the present length of options already contained
//	If header to long, returns -1 without doing anything, otherwise 0
//	We currently disregard from security material
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_MPjoin_syn(unsigned char *top, uint16_t *len, uint32_t token,
		uint32_t rand_nmb, unsigned char addr_id, unsigned char backup) {

	if((*len) + 12 > 40) return 0;

	unsigned char *start = top + (*len);

	if(backup > 1) backup = 1;
	*(start) = MPTCP_KIND;
	*(start+1) = 12;
	*(start+2) = ( ( ((unsigned char) MPTCP_JOIN)<<4) + backup);
	*(start+3) = addr_id;
	*((uint32_t*) (start+4)) = token;
	*((uint32_t*) (start+8)) = rand_nmb;
	(*len) += 12;
	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPJOIN option: SYNACK
//	top points to the beginning of the TCP options
//	len provides the present length of options already contained
//	If header to long, returns -1 without doing anything, otherwise 0
//	We currently disregard from security material
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_MPjoin_synack(unsigned char *top, uint16_t *len, uint32_t *mac,
		uint32_t rand_nmb, unsigned char addr_id, unsigned char backup) {

	if((*len) + 16 > 40) return 0;

	unsigned char *start = top + (*len);
	if(backup > 1) backup = 1;
	*(start) = MPTCP_KIND;
	*(start+1) = 16;
	*(start+2) = ( ( ((unsigned char) MPTCP_JOIN)<<4) + backup);
	*(start+3) = addr_id;
	*((uint32_t*) (start+4)) = mac[0];
	*((uint32_t*) (start+8)) = mac[1];
	*((uint32_t*) (start+12)) = rand_nmb;
	(*len) += 16;
	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPJOIN option: ACK
//	top points to the beginning of the TCP options
//	len provides the present length of options already contained
//	If header to long, returns -1 without doing anything, otherwise 0
//	We currently disregard from security material
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_MPjoin_ack(unsigned char *top, uint16_t *len, uint32_t *mac) {

	if((*len) + 24 > 40) return 0;

	unsigned char *start = top + (*len);
	*(start) = MPTCP_KIND;
	*(start+1) = 24;
	*(start+2) = ( ((unsigned char) MPTCP_JOIN)<<4) ;
	*(start+3) = 0;

	memcpy(start+4, (unsigned char*) mac, 20);
	(*len) += 24;
	return 1;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//create DSS option with DAN only: used only for side ACKs
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_dan_MPdss(unsigned char *mpbuf, uint16_t *mplen) {

	*(mpbuf) = MPTCP_KIND;
	*(mpbuf+1) = 8;
	*(mpbuf+2) = ( ((unsigned char) MPTCP_DSS)<<4) & 0xf0;
	*(mpbuf+3) = 0;
	*(mpbuf+3) += (dssopt_out.Rflag & 0x01)<<5;
	*(mpbuf+3) += (dssopt_out.Fflag & 0x01)<<4;
	*(mpbuf+3) += dssopt_out.Aflag & 0x01;
	*((uint32_t*) (mpbuf+4)) = htonl(dssopt_out.dan);
	*mplen += 8;
	return;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//create DSS option: uses dssopt_out as input
//	mpbuf points to the beginning of the buffer for the TCP option
//	len provides the present length of options already contained
//	We currently disregard checksum
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_complete_MPdss(unsigned char *mpbuf) {
	unsigned char tpdss_len = (dssopt_out.Aflag)? 8:4;//4 bytes min, 8bytes if dan present
	tpdss_len += (dssopt_out.Mflag)? 10:0;//add 8bytes more for dsn and ssn

	packd.mptcp_opt_len += tpdss_len;
	*(mpbuf) = MPTCP_KIND;
	*(mpbuf+1) = tpdss_len;
	*(mpbuf+2) = ( ((unsigned char) MPTCP_DSS)<<4) & 0xf0;
	*(mpbuf+3) = 0;
	*(mpbuf+3) += (dssopt_out.Rflag & 0x01)<<5;
	*(mpbuf+3) += (dssopt_out.Fflag & 0x01)<<4;
	*(mpbuf+3) += (dssopt_out.mflag & 0x01)<<3;
	*(mpbuf+3) += (dssopt_out.Mflag & 0x01)<<2;
	*(mpbuf+3) += (dssopt_out.aflag & 0x01)<<1;
	*(mpbuf+3) += dssopt_out.Aflag & 0x01;

	unsigned char it=0;
	if(dssopt_out.Aflag) {
		*((uint32_t*) (mpbuf+4)) = htonl(dssopt_out.dan);
		it+=4;
	}
	if(dssopt_out.Mflag) {
		*((uint32_t*) (mpbuf+4+it)) = htonl(dssopt_out.dsn);
		*((uint32_t*) (mpbuf+8+it)) = htonl(dssopt_out.ssn);
		*((uint16_t*) (mpbuf+12+it)) = htons(dssopt_out.range);
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPprio option: 
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_MPprio4(unsigned char *mpbuf, unsigned char addr_id_loc, unsigned char backup) {
	*(mpbuf) = MPTCP_KIND;
	*(mpbuf+1) = 4;
	*(mpbuf+2) = ( ((unsigned char) MPTCP_PRIO)<<4) + backup;
	*(mpbuf+3) = addr_id_loc;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPprio option: 
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_MPprio3(unsigned char *mpbuf, unsigned char backup) {
	*(mpbuf) = MPTCP_KIND;
	*(mpbuf+1) = 3;
	*(mpbuf+2) = ( ((unsigned char) MPTCP_PRIO)<<4) + backup;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPremove_addr_option: 
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_MPremove_addr(unsigned char *mpbuf, unsigned char addr_id_loc) {
	*(mpbuf) = MPTCP_KIND;
	*(mpbuf+1) = 4;
	*(mpbuf+2) = ( ((unsigned char) MPTCP_REMOVE_ADDR)<<4);
	*(mpbuf+3) = addr_id_loc;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//create TP_RESET option
//	mpbuf points to packd.tptop_opt_buf.
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_MPreset(unsigned char *mpbuf, uint32_t *key_rem) {
	unsigned char tpcap_len = 12;
	if(packd.mptcp_opt_len + tpcap_len > 40) return 0;

	packd.mptcp_opt_len += tpcap_len;
	*(mpbuf) = MPTCP_KIND;
	*(mpbuf+1) = tpcap_len;
	*(mpbuf+2) = ( ((unsigned char) MPTCP_RST)<<4) & 0xf0;
	*(mpbuf+3) = 1;//no checksum

	*((uint32_t*) (mpbuf+4)) = key_rem[0];
	*((uint32_t*) (mpbuf+8)) = key_rem[1];
	return 1;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//create new packet:
//   Copies IPv4 header, tcp-core header + payload from packd.buf to packd.new_buf
//   Replaces tcp_opt with tcp_opt_buf
//   Sets packd.ipv and packd.tcph to new_buf
// 	Checksums are fixed in filter05 based on verdict!
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_new_packet(unsigned char *const tcp_opt_buf, uint16_t len){
	//add ipv4 header, core tcp header
	memmove(packd.new_buf, packd.buf, packd.ip4len + 20);

	//add new TCP options
	memmove(packd.new_buf + packd.ip4len + 20, tcp_opt_buf, len);

	//add old payload
	memmove(packd.new_buf + packd.ip4len + 20 + len, packd.buf + packd.pos_pay, packd.paylen);

	//update packd
	packd.tcplen = 20 + len;
	packd.pos_pay = packd.pos_thead + packd.tcplen;
	packd.totlen = packd.ip4len + packd.tcplen + packd.paylen;
	packd.ip4h = (struct ipheader*) (packd.new_buf+packd.pos_i4head);
	packd.tcph = (struct tcpheader*) (packd.new_buf+packd.pos_i4head+packd.ip4len);

	//add new tcp header length into packet
	packd.tcph->th_off = packd.tcplen>>2;


	//fix_checksums(packd.new_buf, packd.ip4len, packd.totlen);
	packd.tcp_opt_len = len;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//find  TP option: evaluates TP option array for some subkind
//++++++++++++++++++++++++++++++++++++++++++++++++
inline int find_MPsubkind(struct mptcp_option * const mptopt, size_t nb_options, const unsigned char subkind) {
	unsigned i=0;
	if(nb_options == 0)
		return -1;	

	while(i<nb_options && (((mptopt[i].byte3)>>4) & 0x0f) != subkind ) {
		i++;
	}

	return (i==nb_options)? -1 : (int)i;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//analyzes TPTCP cap  option
//  Finds TPcap in in mptcp_option array
//  Extracts IDSNloc and IDSNrem
// returns 0 if header not found or too short
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPcap(struct mptcp_option * const mptopt, size_t const nb_topt, uint32_t *key_loc, uint32_t *key_rem) {
	int it = find_MPsubkind(mptopt, nb_topt, MPTCP_CAP);
	if(it < 0)
		return 0;

	if(mptopt[it].len != 12 && mptopt[it].len != 20 )
		return 0;


	key_rem[0] = *(uint32_t *) (mptopt[it].data);
	key_rem[1] = *(uint32_t *) (mptopt[it].data + 4);
	
	//both IDSNrem present
	if(mptopt[it].len == 20){
		key_loc[0] = *(uint32_t *) (mptopt[it].data +8);
		key_loc[1] = *(uint32_t *) (mptopt[it].data +12);

	}
	//WTF ?
	//else key_loc == NULL;

	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//analyzes TPTCP join_syn option
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPjoin_syn(struct mptcp_option * const mptopt, size_t const nb_topt, 
	uint32_t *token, uint32_t *rand_nmb, unsigned char *address_id, unsigned char *backup) {

	int it = find_MPsubkind(mptopt, nb_topt, MPTCP_JOIN);

	if(it < 0)
		return 0;

	if(mptopt[it].len != 12)
		return 0;

	//get token and find session
	*address_id = (mptopt[it].byte4);
	*backup = (mptopt[it].byte4 & 0x01);
	*token = (*(uint32_t *) (mptopt[it].data));
	*rand_nmb = * (uint32_t *) (mptopt[it].data+4);

	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//analyzes TPTCP join  synack option
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPjoin_synack(struct mptcp_option * const mptopt, size_t const nb_topt,
		uint32_t *mac, uint32_t *rand_nmb, unsigned char *address_id, unsigned char *backup) {

	int it = find_MPsubkind(mptopt, nb_topt, MPTCP_JOIN);
	if(it < 0)
		return 0;

	if(mptopt[it].len != 16)
		return 0;

	//get token and find session
	*backup = (mptopt[it].byte4 & 0x01);
	*address_id = (mptopt[it].byte4);
	*mac = *( (uint32_t *) (mptopt[it].data)) ;
	*(mac + 1) = *( (uint32_t *) (mptopt[it].data + 4));
	*rand_nmb = * (uint32_t *) (mptopt[it].data + 8);

	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//analyzes TPTCP join ack option
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPjoin_ack(struct mptcp_option * const mptopt, size_t const nb_topt, uint32_t *mac) {

	int it = find_MPsubkind(mptopt, nb_topt, MPTCP_JOIN);

	if(it < 0)
		return 0;

	if(mptopt[it].len != 24)
		return 0;

	//get token and find session
	int i;
	for(i=0;i<5;i++) {
		*(mac + i) = *( (uint32_t *) (mptopt[it].data + 4*i));
	}
	return 1;
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//analyze TPTCP dss option (we already know that this is a dss option)
//  writes on dssopt
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPdss(struct mptcp_option *const tptop, size_t const nb_topt) {

	int i1 = find_MPsubkind(mptopt, nb_topt, MPTCP_DSS);
	if(i1 < 0) {
		dssopt_in.present = 0;
		return 0;
	}

	dssopt_in.present = 1;
	dssopt_in.Rflag = (tptop[i1].byte4 & 0x20)>>5;
	dssopt_in.Fflag = (tptop[i1].byte4 & 0x10)>>4;
	dssopt_in.mflag = (tptop[i1].byte4 & 0x08)>>3;
	dssopt_in.Mflag = (tptop[i1].byte4 & 0x04)>>2;
	dssopt_in.aflag = (tptop[i1].byte4 & 0x02)>>1;
	dssopt_in.Aflag =  tptop[i1].byte4 & 0x01;

	//we assume that aflag and mflag are always 0
	size_t i2 = 0;
	if(dssopt_in.Aflag) {
		if(tptop[i1].len<8) return 0;
		dssopt_in.dan = ntohl( *((uint32_t*) tptop[i1].data));
		i2 = 4;
	}
	if(dssopt_in.Mflag) {
		if(tptop[i1].len<12+i2) return 0;
		dssopt_in.dsn = ntohl( *((uint32_t*) (tptop[i1].data+i2)));
		dssopt_in.ssn = ntohl( *((uint32_t*) (tptop[i1].data+i2+4)));
		dssopt_in.range = ntohs( *((uint16_t*) (tptop[i1].data+i2+8)));
	}
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//analyze TPprio option: 
//	Returns 0 if subkind not found, 1 if 3-bytes (no addr_id_rem), 2 if 4-bytes (incl addr_id_rem)
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPprio(struct mptcp_option *const tptop, size_t const nb_topt,
		unsigned char *addr_id_rem, unsigned char *backup) {

	int i1 = find_MPsubkind(mptopt, nb_topt, MPTCP_PRIO);
	if(i1 < 0)
		return 0;

	*backup = tptop[i1].byte3 & 0x0f;
	*addr_id_rem = 0;
	if(tptop[i1].len == 3) {
		return 1;
	} else {
		*addr_id_rem = tptop[i1].byte4;
		return 2;
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//analyze TPprio option: 
//	If header to long, returns -1 without doing anything, otherwise 0
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPremove_addr(struct mptcp_option *const tptop, size_t const nb_topt, unsigned char *addr_id_rem) {
	int i1 = find_MPsubkind(mptopt, nb_topt, MPTCP_REMOVE_ADDR);
	if(i1 < 0)
		return 0;

	*addr_id_rem = tptop[i1].byte4;
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//analyzes TPTCP reset  option
//  Finds TPcap in in mptcp_option array
//  Extracts IDSNloc and IDSNrem
// returns 0 if header not found or too short
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPreset(struct mptcp_option * const mptopt, size_t const nb_topt, uint32_t *key_loc) {

	int it = find_MPsubkind(mptopt, nb_topt, MPTCP_RST);
	if(it < 0)
		return 0;

	if(mptopt[it].len != 12)
		return 0;

	key_loc[0] = *(uint32_t *) (mptopt[it].data);
	key_loc[1] = *(uint32_t *) (mptopt[it].data + 4);

	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: prepare_traffic_ack()
// Prepares ack for candidate subflow in parallel to traffic packet on active subflow (thruway)
// Packet only serves to satisfy subflow SSN/SAN consistency.
// It does carries a DAN (4B) and the tcp options contained on the thruway input packet
//++++++++++++++++++++++++++++++++++++++++++++++++
int prepare_top_side_ack() {

	//create tcp_opt_buf_ack for side acks
	//copy tcp_opt_buf to tcp_opt_buf_ack
	packd.tcp_opt_len_ack = packd.tcp_opt_len;//copy over the tcp_opt_len value to avoid that it's updated
	memcpy(packd.tcp_opt_buf_ack, packd.tcp_opt_buf, packd.tcp_opt_len);

	//create dan
	packd.mptcp_opt_len_ack = 0;
	create_dan_MPdss(packd.mptcp_opt_buf_ack, &packd.mptcp_opt_len_ack);

	//append dan to top_ack
	if(!append_TCP_option(packd.tcp_opt_buf_ack, &packd.tcp_opt_len_ack, packd.mptcp_opt_buf_ack, packd.mptcp_opt_len_ack) )
		return 0;
	//pad
	//packd.tcp_opt_len_ack=pad_options_buffer(packd.tcp_opt_buf_ack, packd.tcp_opt_len_ack);
	return 1;
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//output_data_mptcp
//	returns 0 if options don't fit into TCP options header
//	returns 1 if options fit into TCP options header
//++++++++++++++++++++++++++++++++++++++++++++++++
int output_data_mptcp() {

	//parse & compact TCP options on packet, copy to packd.tcp_opt_buf
	if(packd.tcp_options_compacted == 0)
		parse_compact_copy_TCP_options(packd.buf+packd.pos_thead+20, packd.tcplen-20);

	//append mptcp_opt_buf to packd.tcp_opt_buf; packd.tcp_opt_len is extended
	if( !append_TCP_option(packd.tcp_opt_buf, &packd.tcp_opt_len, packd.mptcp_opt_buf, packd.mptcp_opt_len) ) {
		//pad appended options
		packd.tcp_opt_len = pad_options_buffer(packd.tcp_opt_buf, packd.tcp_opt_len);
		return 0;
	}

	//pad appended options
	packd.tcp_opt_len = pad_options_buffer(packd.tcp_opt_buf, packd.tcp_opt_len);

	//create new packet from old packet and appended options
	create_new_packet(packd.tcp_opt_buf, packd.tcp_opt_len);
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//Parse TPTCP TCP Options: Only provides pointers data
//  Provides all TPTCP options in the TOP Optin header
//  Opt_buf points at the beginning of the TCP options header, opt_len is the length of the whole header
//++++++++++++++++++++++++++++++++++++++++++++++++
size_t parse_mptcp_options(unsigned char *opt_buf, uint16_t opt_len, struct mptcp_option tptop[]){

	size_t curs = 0;
	size_t count_tp = 0;
	while(curs < opt_len) {
		if ( *(opt_buf+curs) <= 1) curs++;//those are the one-byte option with kind =0 or kind =1
		else{				
			if( *(opt_buf+curs+1) == 0 )
				break;

			if( *(opt_buf+curs) == MPTCP_KIND) {
				tptop[count_tp].kind= *(opt_buf+curs);
				tptop[count_tp].len= *(opt_buf+curs+1);
				tptop[count_tp].byte3= *(opt_buf+curs+2);
				if(tptop[count_tp].len>3) tptop[count_tp].byte4= *(opt_buf+curs+3);
				if(tptop[count_tp].len>4) memmove( tptop[count_tp].data, (opt_buf+curs+4), *(opt_buf+curs+1)-4);

				count_tp++;
			}
			curs+= (*(opt_buf+curs+1));
		}
	}
	return count_tp;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//eliminate_sack(): searches for SACK option (kind = 4, length =2)
//	end eliminates it
//	buf points at beginning of TCP options, 
//	buf and plen are being overwritten
//++++++++++++++++++++++++++++++++++++++++++++++++
int eliminate_sack(unsigned char *buf, unsigned char *len) {
	unsigned char offset = 0;
	int found = 0;
	
	while(offset < *len-1 && !found) {
		if( *(buf+offset) == 4) {
			memmove(buf+offset, buf+offset+2, *len-offset-2);
			*len -= 2;
			found = 1;
		}
		if(*(buf+offset) <=1) offset +=1;
		else offset += *(buf+offset+1);
	}
	return found;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//append_sack(): appends sack option (kind = 4, length =2) to SYN packets
//++++++++++++++++++++++++++++++++++++++++++++++++
int append_sack(unsigned char *buf, unsigned char *len) {
	if(*len > 38)
		return 0;

	*(buf + *len) = 4;
	*(buf + *len + 1) = 2;
	*len += 2;
	return 1;	
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//extract_sack_blocks(): searches for SACK blocks in data packet (kind = 5, length =X)
//	and writes them to sack array sorted in ascending order. 
//	entry sack[0] is reserved for [old SAN-1, new SAN-1]
//	buf points at beginning of TCP options, 
//	nb_sack provides the number of SACK entries found
//++++++++++++++++++++++++++++++++++++++++++++++++
void extract_sack_blocks(unsigned char * const buf, const uint16_t len, unsigned char *nb_sack, uint32_t *sack, uint32_t sack_offset) {
	//find sack offset
	int offset = find_offset_of_tcp_option(buf, len, 5);
	if(offset == -1){
		*nb_sack = 0;
		return;
	}

	//get nb_sack
	*nb_sack = ( *(buf + offset + 1) -2)>>3; // nb of blocks = (len-2)/8
	if(*nb_sack > MAX_SACK_PACKET_ENTRIES) *nb_sack = MAX_SACK_PACKET_ENTRIES;

	//extract blocks and sort
	int i,j,k;
	offset += 2;
	uint32_t lowval;
	for(i=0;i<*nb_sack;i++) {
		//find position in sack array
		j=0;
		lowval = ntohl( *((uint32_t*) (buf + offset)));

		//sort in
		while(j < i && lowval > *(sack + ((j+1)<<1))) j++;

		//move all higher elements one up
		for(k=i-1; k>=j; k--) {
			*(sack + ((k+2)<<1)) = *(sack + ((k+1)<<1));
			*(sack + ((k+2)<<1) + 1) = *(sack + ((k+1)<<1) + 1);
		}

		//enter new value		
		*(sack + ((j+1)<<1)) = lowval + sack_offset;
		*(sack + ((j+1)<<1) + 1) = ntohl( *((uint32_t*) (buf + offset + 4))) + sack_offset - 1;//subtract one since we define upper sack edge differently
		offset += 8;
	}
	return;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//modify_sack(): finds SACK in buf, *len (kind = 5, length =X)
//	and overwrites entries with nb_sack held in sack*
//	if more space is needed and available, rest of TCP options is moved back
//	if less space is needed (fewer entries), rest of TCP options is moved up
//	if no new sack but old sack exists in TCP options, they are removed
//	len is the present TCP opiton length and is updated when new SACK is inserted
//	buf points to beginning of TCP options,
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_sack_blocks(unsigned char nb_sack, uint32_t * const sack,
		unsigned char *buf, uint16_t *len, unsigned char max_len, uint32_t sack_offset) {

	//find sack offset
	int offset = find_offset_of_tcp_option(buf, *len, 5);

	unsigned char nb_curr;
	uint16_t room = max_len - (*len);
	if(max_len < *len)
		room = 0;

	if(offset == -1) {

		offset = *len;
		nb_curr = 0;
		if(room < 10 || nb_sack == 0) return;
		if( nb_sack > ((room-2)>>3) ) nb_sack = ((room-2)>>3);// nb_sack = min(nb_sack, (room-2)/8)

		*(buf+offset) = 5;//set kind
		*(buf+offset+1) = 2 + (nb_sack<<3);//set len
		*len += *(buf+offset+1);//increment total len
	} else {
		nb_curr = (( *(buf + offset + 1) )-2)>>3; // nb of existing SACK entries = (len-2)/8

		unsigned char nb_curr_corr = nb_curr;//room correction to accomodate overhanding bytes
		if(*len > max_len) {
			unsigned char nb_sack_red = ((*len - max_len + 7)>>3);
			if(nb_sack_red > nb_curr_corr) nb_curr_corr = 0;
			else nb_curr_corr -= nb_sack_red;
		}

		if(nb_sack > nb_curr_corr)
			nb_sack = nb_curr_corr + (room>>3);// nb_sack = min(nb_sack, nb_curr+room/8)

		if(nb_sack == 0) {
			memmove(buf + offset, buf + offset+2 + (nb_curr<<3), *len - offset-2 - (nb_curr<<3));
			*len -= (nb_curr<<3) + 2;
			return;
		}
		memmove(buf + offset+2 + (nb_sack<<3), buf + offset+2 + (nb_curr<<3), *len - offset-2 - (nb_curr<<3));
		*(buf+offset+1) = 2 + (nb_sack<<3);//length update
		*len += (nb_sack<<3);
		*len -= (nb_curr<<3);
	}
	unsigned char i;
	offset += 2;
	for(i=0;i<nb_sack;i++) {
		*((uint32_t*) (buf+offset)) = htonl(*(sack + (i<<1))  + sack_offset);
		*((uint32_t*) (buf+offset + 4)) = htonl(*(sack + (i<<1) +1) + sack_offset + 1);//add one since we define upper sack edge differently
		offset += 8;
	}
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//eliminate_tcp_option(): searches for tcp option with certain kind and eliminates it
//	buf and len are updated accordingly
//	return 0 if option was not present and 1 otherwise
//++++++++++++++++++++++++++++++++++++++++++++++++
int eliminate_tcp_option(unsigned char *buf, unsigned char *len, unsigned char kind) {
	unsigned char offset = 0;
	int found = 0;
	
	while(offset < *len-1 && !found) {
		
		if( *(buf+offset) == kind) {
			*len -= *(buf+offset+1);//subtract SACK length
			memmove(buf+offset, buf+offset+ *(buf+offset+1), *len-offset);
			found = 1;
			break;
		}
		if(*(buf+offset) <=1) offset +=1;
		else offset += *(buf+offset+1);
	}
	return found;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//find_tcp_option(): searches for tcp option with certain kind; len is length of option
//++++++++++++++++++++++++++++++++++++++++++++++++
int find_tcp_option(unsigned char *buf, unsigned char  len, unsigned char kind) {

	unsigned char offset = 0;
	int found = 0;
	
	while(offset < len-1 && !found) {
		if( *(buf+offset) == kind) {
			found = 1;
			break;
		}
		if(*(buf+offset) <=1) offset +=1;
		else offset += *(buf+offset+1);
	}
	return found;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//find_offset_of_tcp_option(): searches for tcp option with certain kind and returns offset to beginning of option
//++++++++++++++++++++++++++++++++++++++++++++++++
int find_offset_of_tcp_option(unsigned char *buf, unsigned char  len, unsigned char kind) {

	unsigned char offset = 0;
	int found = -1;
	
	while(offset < len-1 && found == -1) {
		if( *(buf+offset) == kind) {
			found = offset;
			break;
		}
		if(*(buf+offset) <=1) offset +=1;
		else offset += *(buf+offset+1);
	}
	return found;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//add_tcp_option(): adds tcp option in front of buffer
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_tcp_option(unsigned char *buf, uint16_t len, unsigned char opt_kind, unsigned char opt_len, unsigned char *opt_data) {
	memmove(buf + opt_len, buf, len);//shift everything to the back
	*buf = opt_kind;
	*(buf+1) = opt_len;
	memcpy(buf+2, opt_data, opt_len-2);
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//get_timestamp(): searches for timestamp option (kind = 8, length =10)
//	and returns TSVAL or TSECR based on flag (0,1)
//++++++++++++++++++++++++++++++++++++++++++++++++
uint32_t get_timestamp(unsigned char *buf, unsigned char len, unsigned char flag) {
	int pos = find_offset_of_tcp_option(buf, len, 8);
	
	return ntohl( *(uint32_t*)(buf + pos + 2 + (flag<<2) ));

}


//++++++++++++++++++++++++++++++++++++++++++++++++
//set_timestamps(): searches for timestamp option (kind = 8, length =10)
//	and overwrites timestamps. 
//++++++++++++++++++++++++++++++++++++++++++++++++
void set_timestamps(unsigned char *buf, unsigned char len,
		uint32_t tsval, uint32_t tsecr, int tsecr_flag) {

	int pos = find_offset_of_tcp_option(buf, len, 8);
	
	* ( (uint32_t*)(buf+pos+2) ) = htonl(tsval);
	if(tsecr_flag) *( (uint32_t*)(buf+pos+6) ) = htonl(tsecr);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//add_timestamps(): adds timestamps at *buf, updates len
//	and overwrites timestamps. 
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_timestamps(unsigned char *buf, uint32_t tsval, uint32_t tsecr) {
	buf[0] = 8;
	buf[1] = 10;
	*((uint32_t*) (buf+2)) = htonl(tsval);
	*((uint32_t*) (buf+6)) = htonl(tsecr);
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//manipulate_mss(): searches for MSS option (kind = 2, length =4)
//	end overwrite max MSS size with 1420
//++++++++++++++++++++++++++++++++++++++++++++++++
void manipulate_mss(unsigned char *buf, unsigned char *len) {
	unsigned char offset = 0;
	
	//find tcp option with kind=2
	while(offset < *len-1 &&  *(buf+offset) != 2 ){

		if(*(buf+offset) <=1) offset +=1;
		else offset += *(buf+offset+1);
	}

	//deactivate this feature
	if( *(buf+offset) == 2)	*((uint16_t*) (buf + offset + 2)) = htons(MAX_MSS);
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//find_window_scaling(): searches for window scale option and returns factor (kind = 3, length =3)
//	if not found returns 0
//	factor is exponent of 2
//++++++++++++++++++++++++++++++++++++++++++++++++
unsigned char find_window_scaling(unsigned char *buf, unsigned char *len) {
	unsigned char offset = 0;
	unsigned char factor = 0;
	while(offset < *len-2){
		
		if( *(buf+offset) == 3){
			factor = *(buf+offset+2);
			break;
		}
		if(*(buf+offset) <=1) offset +=1;
		else offset += *(buf+offset+1);

	}
	return factor;
}





//++++++++++++++++++++++++++++++++++++++++++++++++
//Parse TCP Options
//  Provides all TCP options in the TOP Optin header
//  Opt_buf pints at the beginning of the TCP options header
//++++++++++++++++++++++++++++++++++++++++++++++++
size_t parse_options(unsigned char *opt_buf, uint16_t opt_len, struct tcp_option top[]) {

	uint16_t offset = 0;
	size_t count = 0;
	while(offset < opt_len) {
		top[count].kind= *(opt_buf+offset);
		if (top[count].kind <= 1){
			top[count].len=1;
			top[count].data[0]=0;
		} else {				
			top[count].len= *(opt_buf+offset+1);
			memmove(top[count].data, (opt_buf+offset+2), top[count].len-2);
		}
		offset+=top[count].len;		
		count++;
	}
	return count;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//Parse Compact TCP Options
//  Provides all TCP options in the TOP Optin header
//  Opt_buf pints at the beginning of the TCP options header
//  All PADs and NO-OPERATIONs are filtered out.
//  This subrouting is used to gain space when more options are to be added
//++++++++++++++++++++++++++++++++++++++++++++++++
size_t parse_compact_options(unsigned char *opt_buf, uint16_t opt_len, struct tcp_option top[]) {

	size_t offset = 0;
	size_t count = 0;
	while(offset < opt_len) {
		if (*(opt_buf+offset) <= 1) {
			offset++;
		} else {				
			top[count].kind= *(opt_buf+offset);
			top[count].len= *(opt_buf+offset+1);
			memmove(top[count].data, opt_buf+offset+2, top[count].len);
			offset+=top[count].len;	
			count++;
		}
	}
	return count;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//Copy options to buffer
//  Pad with zeros
//  Ideally, the tcp options array should not contain kind=0,1,
//  however this is not mandatory requirement here
//  returns the length of the new TCP option header
//++++++++++++++++++++++++++++++++++++++++++++++++
uint16_t copy_options_to_buffer(unsigned char *buf, size_t nb_opt, struct tcp_option top[]) {
	//copy options to buffer
	uint16_t curs=0;
	for(uint16_t i=0;i<nb_opt;i++) {
		memmove(buf+curs, &topt[i], top[i].len);
		curs+=top[i].len;
	}
	return curs;	
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//Pad options buffer 
//  Pad with ones until length is multiple of 4
//  returns the length of the new TCP option header
//++++++++++++++++++++++++++++++++++++++++++++++++
uint16_t pad_options_buffer(unsigned char *buf, uint16_t len) {
	memset(buf+len,1,(((len+3)>>2)<<2)-len);
	return (((len+3)>>2)<<2);
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//New IPv4 header checksum calculation
//++++++++++++++++++++++++++++++++++++++++++++++++
uint16_t i4_sum_calc(uint16_t nwords, uint16_t* buf) {
	//buffer present checksum
	uint16_t sum_buf = ( *(buf+5) );

	//set pointer to checksum on packet
	uint16_t *pt_sum =  buf+5;

	//set packet checksum to zero in order to compute checksum
	*pt_sum = htons(0);

	//initialize sum to zero
	uint32_t sum = 0;

	//sum it all up	
	int i;
	for (i=0; i<nwords; i++)
		sum += *(buf+i);
	
	//keep only the last 16 bist of the 32 bit calculated sum and add the carries
	while(sum>>16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	//take the one's copliement of sum
	sum = ~sum;

	//reinstall original i4sum_buf
	*pt_sum = (uint16_t) (sum_buf);

	//reinstate prior value
	( *(buf+5) ) = sum_buf;

	return sum;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//buffer_tcp_header_checksum()
//  buffers checksum of tcp header only
//  contained in packd. 
//  Does not include payload in sum.
//  
//++++++++++++++++++++++++++++++++++++++++++++++++
void buffer_tcp_header_checksum() {

	if(packd.paylen == 0) {
		packd.old_tcp_header_checksum = (uint16_t) ~packd.tcph->th_sum;
	} else {
		
		//create 16-bit word pointer
		uint16_t *pt_buf16 = (uint16_t *) (packd.buf);	

		//compute checksum. Note: Totlen may have changed during manipulation. It is therefore updated.
		packd.old_tcp_header_checksum = tcp_sum_calc(packd.tcplen, pt_buf16+6, pt_buf16+8, (pt_buf16 + (packd.pos_thead>>1)));
	}
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//New TCP header checksum calculation
//++++++++++++++++++++++++++++++++++++++++++++++++
uint16_t  tcp_sum_calc(
	uint16_t len_tcp, 
	uint16_t *src_addr, 
	uint16_t *dst_addr, 
	uint16_t *buf) {

	//buffer checksum
	uint16_t old_sum = buf[8];//checksum

	//pointer to tcp sum
	uint16_t *pt_sum = buf+8;

	//replace checksum with 0000
	*pt_sum = 0;

	uint16_t prot_tcp = 6;
	uint16_t padd = 0;
	uint32_t sum;

	//Find out if the length of data is even or odd number. If odd,
	//add a padding byte = 0 at the end of packet
	if( (len_tcp & 1) == 1) {
		padd = 1;
		buf[ (len_tcp-1)>>1 ] &= 0x00FF;
	}

	//initialize sum to zero
	sum = 0;

	//make 16 bit words out of every two adjacent 8 bit words and
	//calculate the sum of all 16 bit words
	int i;
	for (i=0; i<((len_tcp+padd)>>1); i++)
		sum +=  (*(buf + i));


	//add the TCP pseudo header which contains
	//the ip srouce and ip destination addresses
	sum +=  (*src_addr);
	sum +=  (*(src_addr + 1));
	sum +=  (*dst_addr);
	sum +=  (*(dst_addr + 1));

	//the protocol number and the length of the TCP packet
	sum += htons(prot_tcp);
	sum += htons(len_tcp);

	//keep only the last 16 bist of the 32 bit calculated sum and add the carries
	while (sum>>16) sum = (sum & 0xFFFF) + (sum >> 16);


	//reinstate buffered checksum
	*pt_sum = old_sum;

	return (uint16_t) sum;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//Fix checksums: Fixes i4 & TCP checksums for manipulated packets
// buf starts at i4 header. len_pk includes i4 header, tcp header, payload
// leni4: length of Ipv4 header in octects, lenpk: length of entire packet in octets
//++++++++++++++++++++++++++++++++++++++++++++++++
void fix_checksums(unsigned char *buf, uint16_t leni4, uint16_t lenpk) {

	//create 16-bit word pointer
	uint16_t *pt_buf16 = (uint16_t *) (buf);	

	//update len_pk in IPv4 header
	*(pt_buf16+1) = (uint16_t) htons(lenpk);	
	
	//update i4 checksum
	uint16_t i4sum = i4_sum_calc( (leni4>>1), pt_buf16);

	//enter fixed i4 checksum into packet
	*(pt_buf16 + 5) = i4sum;

	//delta method
	uint16_t new_tcp_header_checksum = tcp_sum_calc(packd.tcplen, pt_buf16+6, pt_buf16+8, (uint16_t *) (buf + packd.pos_thead));


	uint32_t old_header = (uint16_t) (packd.old_tcp_header_checksum);//without ~
	uint32_t alt_sum_long =  (uint16_t)(~packd.tcph->th_sum) + (uint16_t)(new_tcp_header_checksum);
	alt_sum_long -= ( alt_sum_long <= old_header)? 1:0;
	alt_sum_long -=  old_header;

	while (alt_sum_long>>16)
		alt_sum_long = (alt_sum_long & 0xFFFF) + (alt_sum_long >> 16);
	uint16_t alt_sum = (uint16_t)(~alt_sum_long);


	*(pt_buf16 + (leni4>>1) + 8) = alt_sum;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//compute checksums: computes i4 & TCP checksums for new packets
// buf starts at i4 header. len_pk includes i4 header, tcp header, payload
// leni4: length of Ipv4 header in octects, lenpk: length of entire packet in octets
//++++++++++++++++++++++++++++++++++++++++++++++++
void compute_checksums(unsigned char *buf, uint16_t leni4, uint16_t lenpk) {

	//create 16-bit word pointer
	uint16_t *pt_buf16 = (uint16_t *) (buf);	

	//set checksum to 0
	//*(pt_buf16 + 5) = 0;

	//update len_pk in IPv4 header
	*(pt_buf16+1) = (uint16_t) htons(lenpk);	
	

	//update i4 checksum
	uint16_t i4sum = i4_sum_calc( (leni4>>1), pt_buf16);

	//enter fixed i4 checksum into packet
	*(pt_buf16 + 5) = i4sum;

	//compute checksum. Note: Totlen may have changed during manipulation. It is therefore updated.
	//delta method
	*(pt_buf16 + (leni4>>1) + 8) = 0;
	uint16_t new_tcp_header_checksum = tcp_sum_calc(lenpk-leni4, pt_buf16+6, pt_buf16+8, (uint16_t *) (buf + leni4));


	*(pt_buf16 + (leni4>>1) + 8) = ~( (uint16_t)(new_tcp_header_checksum));
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//verify checksums: verifies i4 & TCP checksums for incoming packets
// buf starts at i4 header. len_pk includes i4 header, tcp header, payload
// leni4: length of Ipv4 header in octects, lenpk: length of entire packet in octets
//returns boolean 0 or 1
//++++++++++++++++++++++++++++++++++++++++++++++++
int verify_checksums(unsigned char *buf) {

	//create 16-bit word pointer
	uint16_t *pt_buf16 = (uint16_t *) (buf);	


	uint16_t lenpk = ntohs( *(pt_buf16+1) );
	uint16_t leni4 = (*buf & 0x0f)<<2;

	//update i4 checksum
	uint16_t sum = *(pt_buf16 + 5);
	if (sum != i4_sum_calc( (leni4>>1), pt_buf16))
		return 0;


	//delta method
	sum = *(pt_buf16 + (leni4>>1) + 8);
	uint16_t new_sum = ~tcp_sum_calc(lenpk-leni4, pt_buf16+6, pt_buf16+8, (uint16_t *) (buf + leni4));
	if(sum != new_sum)
		return 0;

	return 1;
}


