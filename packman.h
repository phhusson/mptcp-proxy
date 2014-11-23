//*****************************************************
//*****************************************************
//
// packman.h 
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


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: create_packet(..)
//	packet written to buf
//	returns *plen 
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void create_packet(unsigned char *buf, uint16_t *plen, 
	struct fourtuple *pft, 
	uint32_t sn, 
	uint32_t an,
	unsigned char flags, 
	uint16_t win, 
	unsigned char *buf_opt, 
	uint16_t len_opt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: send_raw_packet over IP
//++++++++++++++++++++++++++++++++++++++++++++++++
int send_raw_packet(size_t sd, unsigned char *buf, uint16_t len, uint32_t ip_dst);


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: send_reset_fourtuple()
// Sends sest on a certain fourtuple
//++++++++++++++++++++++++++++++++++++++++++++++++
int send_reset_fourtuple(struct fourtuple *ft, uint32_t seq_nb);


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: cache_packet_header: Buffers signaling packet for retransmission purposes
//++++++++++++++++++++++++++++++++++++++++++++++++
void cache_packet_header();

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: retransmit_cached_packet_header:
//   Copies packet buffered in session to new_buf
//++++++++++++++++++++++++++++++++++++++++++++++++
void retransmit_cached_packet_header();


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: int parse_compact_copy_TCP_options(unsigned char *tcp_opt, uint16_t len)
//	bundle a bunch of functions
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void parse_compact_copy_TCP_options(unsigned char *tcp_opt, uint16_t len);

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: append_TCP_option
//	topt is the new option and len its length
//	topt is attached to the options in packet after compacting them
//	If header to long, returns -1 without doing anything, otherwise 0
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int append_TCP_option(unsigned char *tcp_opt, uint16_t *plen, unsigned char *new_tcp_opt, uint16_t new_len);


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: create TPCAP option
//	mpbuf points to packd.tptop_opt_buf.
//	For SYN and SYN/ACK, only IDSN_loc is provided. 
//	For final ACK both IDSNs are provided
//	We currently assume that DSNs have only 4B
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int create_MPcap(unsigned char *mpbuf, uint32_t *key_loc, uint32_t *key_rem);


//++++++++++++++++++++++++++++++++++++++++++++++++
//create_dummy_mptopt(..)
//	creates mpbuf for dummy DSS
//      used when terminating subflows
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_dummy_dssopt(unsigned char *mpbuf);
 
//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPJOIN option: SYN
//	top points to the beginning of the TCP options
//	len provides the present length of options already contained
//	If header to long, returns -1 without doing anything, otherwise 0
//	We currently disregard from security material
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_MPjoin_syn(unsigned char *top, uint16_t *len, uint32_t token, uint32_t rand_nmb, unsigned char addr_id, unsigned char backup);

//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPJOIN option: SYNACK
//	top points to the beginning of the TCP options
//	len provides the present length of options already contained
//	If header to long, returns -1 without doing anything, otherwise 0
//	We currently disregard from security material
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_MPjoin_synack(unsigned char *top, uint16_t *len, uint32_t *mac, uint32_t rand_nmb, unsigned char addr_id, unsigned char backup);

//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPJOIN option: ACK
//	top points to the beginning of the TCP options
//	len provides the present length of options already contained
//	If header to long, returns -1 without doing anything, otherwise 0
//	We currently disregard from security material
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_MPjoin_ack(unsigned char *top, uint16_t *len, uint32_t *mac);


//++++++++++++++++++++++++++++++++++++++++++++++++
//create DSS option with DAN only: uses dssopt_out as input
//	mpbuf points to the beginning of the buffer for the TCP option
//	only used for side ACKS !!!
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_dan_MPdss(unsigned char *mpbuf, uint16_t *mplen);

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: create DSS option
//	top points to the beginning of the TCP options
//	len provides the present length of options already contained
//	We currently disregard data  checksum
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_complete_MPdss(unsigned char *mpbuf);

//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPprio option: 
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_MPprio4(unsigned char *mpbuf, unsigned char addr_id_loc, unsigned char backup);


//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPprio option: 
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_MPprio3(unsigned char *mpbuf, unsigned char backup);


//++++++++++++++++++++++++++++++++++++++++++++++++
//create TPremove_addr_option: 
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_MPremove_addr(unsigned char *mpbuf, unsigned char addr_id_loc);

//++++++++++++++++++++++++++++++++++++++++++++++++
//create TP_RESET option
//	mpbuf points to packd.tptop_opt_buf.
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_MPreset(unsigned char *mpbuf, uint32_t *key_rem);

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: create new packet:
//   Copies IPv4 header, tcp-core header + payload from packd.buf to packd.new_buf
//   Replaces tcp_opt with tcp_opt_buf
//   Sets packd.ipv and packd.tcph to new_buf
// DOES NOT FIX CHECKSUMS!
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void create_new_packet(unsigned char *const tcp_opt_buf, uint16_t len);


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: find  TP option: evaluates TP option array for some subkind
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int find_MPsubkind(struct mptcp_option * const mptopt, size_t nb_options, const unsigned char subkind);


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: analyze TPTCP cap  option
//  Finds TPcap in in mptcp_option array
//  Extracts IDSNloc and IDSNrem
//  If option not found, returns -1 otherwise 0.
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int analyze_MPcap(struct mptcp_option * const mptopt, size_t const nb_topt, uint32_t *key_loc, uint32_t *key_rem);


//++++++++++++++++++++++++++++++++++++++++++++++++
//analyzes TPTCP join_syn option
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPjoin_syn(struct mptcp_option * const mptopt, size_t const nb_topt, \
		uint32_t *token, uint32_t *rand_nmb, unsigned char *address_id, unsigned char *backup);

//++++++++++++++++++++++++++++++++++++++++++++++++
//analyzes TPTCP join  option
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPjoin_synack(struct mptcp_option * const mptopt, size_t const nb_topt, \
		uint32_t *mac, uint32_t *rand_nmb, unsigned char *address_id, unsigned char *backup);

//++++++++++++++++++++++++++++++++++++++++++++++++
//analyzes TPTCP join ack option
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPjoin_ack(struct mptcp_option * const mptopt, size_t const nb_topt, uint32_t *mac);

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: analyze TPTCP dss option
//  writes on dssopt
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int analyze_MPdss(struct mptcp_option *const tptop, size_t const nb_topt);

//++++++++++++++++++++++++++++++++++++++++++++++++
///PACKMAN: analyze TPprio option: 
//	Returns addr_id_rem: When not provided, pointer=NULL
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPprio(struct mptcp_option *const tptop, size_t const nb_topt, unsigned char *addr_id_rem, unsigned char *backup);

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: analyze TPprio option: 
//	If header to long, returns -1 without doing anything, otherwise 0
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPremove_addr(struct mptcp_option *const tptop, size_t const nb_topt, unsigned char *addr_id_rem);

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: analyze TPTCP reset  option
//++++++++++++++++++++++++++++++++++++++++++++++++
int analyze_MPreset(struct mptcp_option * const mptopt, size_t const nb_topt, uint32_t *key_rem);


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: prepare_traffic_ack()
// Prepares ack for candidate subflow in parallel to traffic packet on active subflow (thruway)
// Packet only serves to satisfy subflow SSN/SAN consistency.
// It does carries a DAN (4B) and the tcp options contained on the thruway input packet
//++++++++++++++++++++++++++++++++++++++++++++++++
int prepare_top_side_ack();

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: output_data_tptcp
//	returns 0 if options don't fit into TCP options header
//	returns 1 if options fit into TCP options header
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int output_data_mptcp();



//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: Parse TPTCP TCP Options: Only provides pointers data
//  Provides all TPTCP options in the TOP Optin header
//  Opt_buf points at the beginning of the TCP options header, opt_len is the length of the whole header
//++++++++++++++++++++++++++++++++++++++++++++++++
extern size_t parse_mptcp_options(unsigned char *opt_buf, uint16_t opt_len, struct mptcp_option tptop[]);


//++++++++++++++++++++++++++++++++++++++++++++++++
//eliminate_sack(): searches for SACK option (kind = 4, length =2)
//	end eliminates it
//	buf points at beginning of TCP options, 
//	buf and plen are being overwritten
//++++++++++++++++++++++++++++++++++++++++++++++++
int eliminate_sack(unsigned char *buf, unsigned char  *len);

//++++++++++++++++++++++++++++++++++++++++++++++++
//append_sack(): appends sack option (kind = 4, length =2) to SYN packets
//++++++++++++++++++++++++++++++++++++++++++++++++
int append_sack(unsigned char *buf, unsigned char *len);


//++++++++++++++++++++++++++++++++++++++++++++++++
//extract_sack_blocks(): searches for SACK in data packet (kind = 5, length =X)
//	end eliminates it
//	buf points at beginning of TCP options, 
//	buf and len are being overwritten
//++++++++++++++++++++++++++++++++++++++++++++++++
void extract_sack_blocks(unsigned char * const buf, const uint16_t len, unsigned char *nb_sack, uint32_t *sack, uint32_t sack_offset);



//++++++++++++++++++++++++++++++++++++++++++++++++
//update_sack_blocks(): finds SACK in buf, *len (kind = 5, length =X)
//	and overwrites entries with nb_sack held in sack*
//	if more space is needed, rest of TCP options is moved back
//	if less space is needed (fewer entries, rest of TCP options is moved up
//	len refers to TCP option length and is updated accordingly
//	buf points to beginning of TCP options, 
//	max_len is the maximum length buf can take on
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_sack_blocks(unsigned char nb_sack, uint32_t * const sack, unsigned char *buf, uint16_t *len, unsigned char max_len, uint32_t sack_offset);



//++++++++++++++++++++++++++++++++++++++++++++++++
//eliminate_tcp_option(): searches for tcp option with certain kind and eliminates it
//	buf and len are updated accordingly
//	return 0 if option was not present and 1 otherwise
//++++++++++++++++++++++++++++++++++++++++++++++++
int eliminate_tcp_option(unsigned char *buf, unsigned char *len, unsigned char kind);

//++++++++++++++++++++++++++++++++++++++++++++++++
//find_tcp_option(): searches for tcp option with certain kind
//++++++++++++++++++++++++++++++++++++++++++++++++
int find_tcp_option(unsigned char *buf, unsigned char  len, unsigned char kind);

//++++++++++++++++++++++++++++++++++++++++++++++++
//find_offset_of_tcp_option(): searches for tcp option with certain kind and returns offset to beginning of option
//++++++++++++++++++++++++++++++++++++++++++++++++
int find_offset_of_tcp_option(unsigned char *buf, unsigned char  len, unsigned char kind);


//++++++++++++++++++++++++++++++++++++++++++++++++
//add_tcp_option(): adds tcp option in front of buffer
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_tcp_option(unsigned char *buf, uint16_t len,\
	unsigned char opt_kind, unsigned char opt_len, unsigned char *opt_data);


//++++++++++++++++++++++++++++++++++++++++++++++++
//manipulate_mss(): searches for MSS option (kind = 2, length =4)
//	end overwrite max MSS size with 1420
//++++++++++++++++++++++++++++++++++++++++++++++++
void manipulate_mss(unsigned char *buf, unsigned char *len);


//++++++++++++++++++++++++++++++++++++++++++++++++
//get_timestamp(): searches for timestamp option (kind = 8, length =10)
//	and returns TSVAL or TSECR based on flag (0,1)
//++++++++++++++++++++++++++++++++++++++++++++++++
uint32_t get_timestamp(unsigned char *buf, unsigned char len, unsigned char flag);


//++++++++++++++++++++++++++++++++++++++++++++++++
//set_timestamp(): searches for timestamp option (kind = 8, length =10)
//	and sets TSVAL and TSECR
//++++++++++++++++++++++++++++++++++++++++++++++++
void set_timestamps(unsigned char *buf, unsigned char len, uint32_t tval, uint32_t tsecr, int tsecr_flag);

//++++++++++++++++++++++++++++++++++++++++++++++++
//add_timestamps(): adds timestamps at *buf, updates len
//	and overwrites timestamps. 
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_timestamps(unsigned char *buf, uint32_t tsval, uint32_t tsecr);



//++++++++++++++++++++++++++++++++++++++++++++++++
//find_window_scaling(): searches for window scale option and returns factor (kind = 3, length =3)
//	if not found returns 0
//	factor is exponent of 2
//++++++++++++++++++++++++++++++++++++++++++++++++
unsigned char find_window_scaling(unsigned char *buf, unsigned char  *len);

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: Parse TCP Options
//  Provides all TCP options in the TOP Optin header
//  Opt_buf pints at the beginning of the TCP options header
//++++++++++++++++++++++++++++++++++++++++++++++++
extern size_t parse_options(unsigned char *opt_buf, uint16_t opt_len, struct tcp_option top[]);


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: Parse Compact TCP Options
//  Provides all TCP options in the TOP Optin header
//  Opt_buf pints at the beginning of the TCP options header
//  All PADs and NO-OPERATIONs are filtered out.
//  This subrouting is used to gain space when more options are to be added
//++++++++++++++++++++++++++++++++++++++++++++++++
extern size_t parse_compact_options(unsigned char *opt_buf, uint16_t opt_len, struct tcp_option top[]);


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: Add TCP option
//  nb_opt is the number of current optins
//  returns -1 if length is exceeded, otherwise the new length of the options.
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int add_options(size_t *nb_opt, struct tcp_option top[], 
	unsigned char opt_kind,  
	uint16_t opt_len, 
	unsigned char *opt_data);


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: Copy options to buffer
//  returns the length of the new TCP option header
//++++++++++++++++++++++++++++++++++++++++++++++++
extern uint16_t copy_options_to_buffer(unsigned char *buf, size_t nb_opt, struct tcp_option top[]);

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: Pad options buffer 
//  Pad with zeros until length is multiple of 4
//  returns the length of the new TCP option header
//++++++++++++++++++++++++++++++++++++++++++++++++
extern uint16_t pad_options_buffer(unsigned char *buf, uint16_t len);


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: New IPv4 header checksum calculation
//++++++++++++++++++++++++++++++++++++++++++++++++
uint16_t i4_sum_calc(uint16_t nwords, uint16_t* buf);


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: buffer_tcp_header_checksum()
//  buffers checksum of tcp header
//  contained in packd. 
//  Does not include payload in sum.
//  
//++++++++++++++++++++++++++++++++++++++++++++++++
void buffer_tcp_header_checksum();

//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: New TCP header checksum calculation: all in uint16_t
//++++++++++++++++++++++++++++++++++++++++++++++++
extern uint16_t tcp_sum_calc(
	uint16_t len_tcp, 
	uint16_t *src_addr, 
	uint16_t *dst_addr, 
	uint16_t *buf);


//++++++++++++++++++++++++++++++++++++++++++++++++
//PACKMAN: Fix checksums: Fixes i4 & TCP checksums for manipulated packets
// buf starts at i4 header. len_pk includes i4 header, tcp header, payload
// leni4: length of Ipv4 header in octects, lenpk: length of entire packet in octets
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void fix_checksums(unsigned char *buf, uint16_t leni4, uint16_t lenpk);

//++++++++++++++++++++++++++++++++++++++++++++++++
//Fix checksums: Fixes i4 & TCP checksums for manipulated packets
// buf starts at i4 header. len_pk includes i4 header, tcp header, payload
// leni4: length of Ipv4 header in octects, lenpk: length of entire packet in octets
//++++++++++++++++++++++++++++++++++++++++++++++++
void compute_checksums(unsigned char *buf, uint16_t leni4, uint16_t lenpk);

//++++++++++++++++++++++++++++++++++++++++++++++++
//verify checksums: verifies i4 & TCP checksums for incoming packets
// buf starts at i4 header. len_pk includes i4 header, tcp header, payload
// leni4: length of Ipv4 header in octects, lenpk: length of entire packet in octets
//returns boolean 0 or 1
//++++++++++++++++++++++++++++++++++++++++++++++++
int verify_checksums(unsigned char *buf);


