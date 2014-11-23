//*****************************************************
//*****************************************************
//
// mptcpproxy_util.c 
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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/time.h>
#include <fcntl.h>

#include "uthash.h"

//Operations
#define UPDATE_DEFAULT_ROUTE 0 //derives new /24 default route in case of mpproxy -B and mpproxy -A
#define USE_PORT_FOR_NEW_SUBFLOWS 0 //after break, use a different port number to establish a new subflow. THis is for testing purpose.
#define ALLOW_PEER_MULTIPATH 0//if 0, backup flag on new subflows is set to 1
#define DO_SACK 1 // 
#define MAX_SACK_PACKET_ENTRIES 4//all higher ones are erased
#define MAX_SACK_BUF_ENTRIES 20//all higher ones are erased
#define MAX_MSS 1400//1420
#define MAX_RETRANSMIT 3//counter for REX
#define MAX_PRIO_EVENTS 3//counter for Prio event

//offset between TCP_SN and initial SFL_SN. Should be 0 so that subflows initiated
//by one side and not supported on the other can fall back to conventional TCP
//without requiring state on the MPTCP side
#define OFFSET_TCP_SN 0 //(1000000000u)//uint32_t value; TCP SEQ - initial SFL SEQ

//time intervals
#define REX_TIME_INTERVAL 2//time interval for retransmissions of subflow signaling data
#define BREAK_TIME_INTERVAL 2//time interval to check on session or subflow break
#define PRIO_TIME_INTERVAL 2//time interval for prio message retransmission conditions
#define CLOSE_TIME_INTERVAL 2//time interval to check if session can be torn down after DATA FIN handshake or SESS_TEARDOWN
#define SESS_TEARDOWN_TIME_INTERVAL 30//time interval to teardown session after after all subflows subsided
#define SFL_TEARDOWN_TIME_INTERVAL 10//time interval to teardown sfl after local interface has discontinued
#define REMOVE_ADDR_TIME_INTERVAL 5//time interval to retransmit remove addr event


//MPTCP kind and subkind data
#define MPTCP_KIND 30
#define MPTCP_CAP 0
#define MPTCP_JOIN 1
#define MPTCP_DSS 2
#define MPTCP_PRIO 5
#define MPTCP_ADD_ADDR 3
#define MPTCP_REMOVE_ADDR 4
#define MPTCP_RST 7

//Data aquisition
#define PRINT_FILE 0
#define PRINT_TABLE 0
#define MAX_PRINT_LINES 36000
#define MAX_MSG_LINES 500
#define MAX_MSG_LENGTH 150
#define FILE_NAME_1 "/tmp/packet_data_1.txt"
#define FILE_NAME_3 "/tmp/packet_data_3.txt"
#define FILE_NAME_10 "/tmp/table_data_1.txt"
#define FILE_NAME_30 "/tmp/table_data_3.txt"
#define FILE_NAME_MSG "/tmp/mptcp_proxy_msg.txt"

//session and subflow states: order very important
#define SYN_SENT 1
#define PRE_SYN_REC_1 2
#define PRE_SYN_REC_2 3
#define SYN_REC 4
#define PRE_EST 5
#define ESTABLISHED 6
#define PRE_CLOSE_WAIT 7
#define CLOSE_WAIT 8
#define FIN_WAIT_1 9
#define FIN_WAIT_2 10
#define PRE_CLOSING 11
#define PRE_TIME_WAIT 12
#define CLOSING 13
#define LAST_ACK 14
#define TIME_WAIT 15
#define RST_WAIT 16
#define CLOSED 17



//subflow init sates
// CLOSED is only used for initial subflow that has been closed.
// The state needs to be kept in memory to recognize the 4-tuple for hook-3 packets
#define ACTIVE 1
#define CANDIDATE 0


//interfaces
#define MAX_LENGTH_IFACE_NAME 20
#define MAX_INTERFACES 10
#define DUMMY_IFACE_NAME "dummy0"


//Event Types
#define RETRANSMIT 0
#define SESS_BREAK 1
#define SFL_BREAK 2
#define PRIO 3
#define SESS_CLOSE 4
#define SFL_CLOSE 5
#define REMOVE_ADDR 6

//forwarding types
#define M_TO_T 1 //1 MPTCP to TCP, behaves like input
#define T_TO_M 3 //3 TCP to MPTCP, behaves like output

//*****GLOBAL DATA and STRUCTS***********


//output messages
//extern unsigned char stop_program;
//extern char message[500];

//netlink socket descriptor to catch interface changes
int nl_sd;
char nl_buf[4096];
struct nlmsghdr *nlh;
int terminate_loop;
char msg_buf[MAX_MSG_LENGTH+1];

//fifo sds
int fd_fifo_dwn;
int fd_fifo_up;

//socket descriptor for raw socket and buffer fo raw socket
extern int raw_sd;
extern unsigned char raw_buf[400] __attribute__ ((aligned));// = malloc( 60 * sizeof(unsigned char));



struct pntArray{

	void **pnts;
	size_t number;//size of elements
	size_t alloc;//number of memory allocated (units of elements)

};


//interface table: Currently available interfaces. We hard code memory allocation for MAX_INTERFACES interfaces
struct if_table{
	size_t nb_if;//number of ifaces
	char ifname[MAX_INTERFACES][MAX_LENGTH_IFACE_NAME];//max length for each interface is 10
	uint32_t ipaddr[MAX_INTERFACES];//host format

	struct pntArray pAalias[MAX_INTERFACES];
	size_t max_alias_index[MAX_INTERFACES];	
}; 
extern struct if_table if_tab1, if_tab2;

/*
//interface structure
//int nb_alias;//number of alias addresses
struct if_alias{
	uint32_t ipaddr;//local address of session - key for table
//	char if_name[MAX_LENGTH_IFACE_NAME];//current interface name
	size_t index;//alias index
//	struct pntArray pA_sess;//list of sessions with this local address
	UT_hash_handle hh;
};
extern struct if_alias *alias_hash;//defined in filter05
*/


//this is the key for subflows
struct fourtuple{
	uint32_t ip_loc;
	uint32_t ip_rem;
	uint16_t prt_loc;
	uint16_t prt_rem;
};



struct ipheader{
	unsigned char ip_h1:4, ip_v:4;//each member is 4 bits
	unsigned char ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
	unsigned char ip_ttl;
	unsigned char ip_p;
	uint16_t ip_sum;
	uint32_t ip_src;
	uint32_t ip_dst;
};

struct tcpheader{
	uint16_t th_sport;
	uint16_t th_dport;
	uint32_t th_seq;
	uint32_t th_ack;
	unsigned char th_x2:4, th_off:4;
	unsigned char th_flags;
	uint16_t th_win;
	uint16_t th_sum;
	uint16_t th_urp;
};

//DSS option data
struct dss_option{
	int present;
	unsigned char Rflag;
	unsigned char Fflag;
	unsigned char mflag;
	unsigned char Mflag;
	unsigned char aflag;
	unsigned char Aflag;
	uint32_t dsn;
	uint32_t dan;
	uint32_t ssn;
	uint16_t range;
};
extern struct dss_option dssopt_in;//defined in sessman
extern struct dss_option dssopt_out;//defined in sessman


struct print_msg{
	uint32_t index;
	struct timeval now;
	char  msg[MAX_MSG_LENGTH];
};


//data struct to print msg
struct print_msg_array{
	FILE *file_msg;	
	struct timeval start;
	struct print_msg **prt_msgs;
	uint32_t nmb_msg;//total number of messages
	uint32_t curr_msg_index;//curr message index in array
};
extern struct print_msg_array prt_msg_array;


//these data will be stored for every packet if PRINT_FILE == 1
struct print_line{
	uint32_t id;
	size_t hook;
	struct timeval now;
	int verdict;	

	size_t sess_id;
	size_t sfl_id;
	int rex;//retransmission

	uint16_t paylen;
	unsigned char flags;
	
	uint32_t ssn;
	uint32_t san;
	uint32_t dsn;
	uint32_t dan;

	unsigned char nb_sack_in;
	uint32_t sack_in[8];

	unsigned char nb_sack_out;
	uint32_t sack_out[8];
};




//these data will be stored for every packet if PRINT_TABLE == 1
struct print_table{
	int nb_entries;

	uint32_t id;
	size_t hook;
	size_t sfl_id;
	uint32_t dsn[10];
	uint32_t ssn[10];
	uint32_t range[10];
};

//data struct to print data
struct print_data{
	int do_print;
	FILE *file1;	
	FILE *file3;
	FILE *file10;
	FILE *file30;
	struct timeval start;
	struct print_line **print_line_array;//array of pointers to print lines
	uint32_t nmb_lines;

	struct print_table **print_table_array;//array of pointers to print table
	uint32_t nmb_tables;

};
extern struct print_data prt_data;

struct packet_data{
	uint32_t id;

	size_t hook;

	size_t fwd_type;//M_TO_T or T_TO_M

	unsigned char *buf;//for incoming packet
	unsigned char new_buf[4096];//for new packet

	//flagged if TCP options have been parsed and compacted
	int tcp_options_compacted;

	//for creating new TCP option header
	unsigned char tcp_opt_buf[200];//40 would be enough. Add more to avoid crashing option_buf temporarilly overuns
	uint16_t tcp_opt_len;

	//for creating new TCP option header for side ACKs
	unsigned char tcp_opt_buf_ack[60];//40 would be enough. Add more to avoid crashing option_buf temporarilly overuns
	uint16_t tcp_opt_len_ack;


	//for creating new TPTCP option header
	unsigned char mptcp_opt_buf[200];//40 would be enough. Add more to avoid crashing option_buf temporarilly overuns
	uint16_t mptcp_opt_len;
	int mptcp_opt_appended;


	//for creating new TPTCP option header for side ACKs
	unsigned char mptcp_opt_buf_ack[200];//40 would be enough. Add more to avoid crashing option_buf temporarilly overuns
	uint16_t mptcp_opt_len_ack;

	//initial ip header positions
	uint16_t pos_i4head;

	//initial tcp header positions (excl ip header length)
	uint16_t pos_thead;

	//initial tcp payload positions (excl ip header length & TCP header length)
	uint16_t pos_pay;

	uint16_t ip4len;
	uint16_t tcplen;
	uint16_t paylen;
	uint16_t totlen;

	struct ipheader *ip4h;
	struct tcpheader *tcph;
	uint16_t header_checksum;

	unsigned char flags;	
	unsigned char syn;
	unsigned char ack;
	unsigned char fin;
	unsigned char rst;

	//sack data
	uint32_t sack_in[2 * MAX_SACK_BUF_ENTRIES + 2];//add 2 for [SANold-1,SANnew-1] 
	uint32_t sack_tcp[2 * MAX_SACK_BUF_ENTRIES + 2];
	unsigned char nb_sack_in;
	unsigned char nb_sack_tcp;

	struct fourtuple ft;
	struct session *sess;
	struct subflow *sfl;

	//for output
	uint32_t dsn_curr_loc;
	uint32_t dan_curr_rem;

	uint16_t paylen_curr;//if paylen of packet has to be reduced
	uint32_t ssn_curr_loc;
	uint32_t san_curr_rem;
	
	//for input
	uint32_t dsn_curr_rem;
	uint32_t dan_curr_loc;
	uint32_t ssn_curr_rem;
	uint32_t san_curr_loc;

	//uint32_t ssn_curr_loc;

	int retransmit_flag;

	int dan_rem_state;//-1: old, 0: not advanced, 1: advanced

	size_t verdict;//1 for accept, 0 for drop
	size_t data_update_flag;//1 if packet has been extended and holds new data
	size_t size_update_flag;//1 if packet has been extended and holds new data

	//size_t thruway_flag;//1 if OUTPUT packet moves through or is terminated
	uint16_t old_tcp_header_checksum;
	uint32_t payload_checksum;

	size_t nb_mptcp_options;

	struct print_line prt_line;
	struct print_table prt_table;
};
extern struct packet_data packd;//defined in filter05


//struct for mapping entries
struct map_entry{
	struct subflow *sfl;
	uint32_t dsn;
	uint32_t ssn;
	uint32_t range;

	struct map_entry *prior;//sfl chain
	struct map_entry *next;//sfl chain
};

struct map_table{
	int size;	
	struct map_entry *top;
	struct map_entry *bot;
	struct map_entry *pnt1;//to add entries or delete entries
	struct map_entry *pnt2;//as memory pointer
	struct map_entry *pnt3;//as memory pointer
};



struct session;

struct subflow{
	struct fourtuple ft;//key
	size_t index;//index in subflow table: do we need this?

	char ifname_loc[MAX_LENGTH_IFACE_NAME];

	struct session *sess;//pointer to session

	int tcp_state;
	int act_state;//activivity state: active or candidate
	int ack_state;//packets have arrived on this subflow with SSNrem+range < SANrem_old

	struct timeval teardown_time;
	int broken;

	unsigned char addr_id_loc;
	unsigned char addr_id_rem;

	uint32_t isn_loc;//init SN local
	uint32_t isn_rem;//init SN remote

	uint32_t csn_loc;//cutoff SN local
	uint32_t csn_rem;//cutoff SN remote

	uint32_t highest_sn_rem;//highest remote sn that was received
	uint32_t highest_an_rem;//highest remote sn that was acked
	uint32_t highest_sn_loc;//highest local sn that was sent out
	uint32_t highest_an_loc;//highest local sn that was acked

	uint32_t curr_an_rem;//this may be smaller than highest_an_rem
	uint32_t last_an_rem;

	int sack_flag;
	uint32_t sack_sfl[2 * MAX_SACK_BUF_ENTRIES + 2];
	unsigned char nb_sack_sfl;
	unsigned char sack_sfl_start;

	uint32_t offset_loc;//DSN_loc - SN_loc
	uint32_t offset_rem;//DSN_rem - SN_rem

	uint32_t rand_nmb_loc;//senders random number used for MP_JOIN
	uint32_t rand_nmb_rem;//senders random number used for MP_JOIN
	struct map_table *map_recv;
	struct map_table *map_send;

	uint32_t tsecr;//host byte order

	UT_hash_handle hh;
};
extern struct subflow *sfl_hash;//defined in sflman


struct subflow_index{
	size_t index;
	struct subflow *sfl;
	UT_hash_handle hh;
};
extern struct subflow_index *sfl_index_hash;

struct subflow_pnt{
	struct subflow *sfl;
	UT_hash_handle hh;
};
extern struct subflow_pnt *sfl_pnt_hash;


struct addrid{
	uint32_t addr;
	unsigned char id;
};

struct session{
	struct fourtuple ft;//key, this is the ft used by the TCP control block

	size_t index;//index in session table: do we need this?
	size_t proxy;


	uint32_t key_loc[2];
	uint32_t key_rem[2];



	uint32_t token_loc;
	uint32_t token_rem;

	uint32_t idsn_loc;//init DSN local
	uint32_t idsn_rem;//init DSN remote

	uint32_t offset_loc;//SN_tcp - DSN
	uint32_t offset_rem;//SN_tcp - DSN

	uint32_t cdsn_loc;//cutoff DSN local
	uint32_t cdsn_rem;//cutoff DSN remote (this is the highest DSN_rem received at cutoff)

	uint32_t highest_dsn_loc;//higest DSN local
	uint32_t highest_dsn_rem;//highest DSN remote
	uint32_t highest_dan_loc;//higest DSN local
	uint32_t highest_dan_rem;//highest DSN remote

	uint32_t last_dan_loc;

	uint32_t fin_dsn_loc;//local fin DSN
	uint32_t fin_dsn_rem;//remote fin DSN


	unsigned char largest_addr_id_loc;
	struct pntArray pA_addrid_loc;//pointer array to local addr/addr-id pairs
	struct pntArray pA_addrid_rem;//pointer array to local addr/addr-id pairs
	struct pntArray pA_sflows;//pointer array to subflow contained in this session
	struct pntArray pA_sflows_data;//pointer array to subflows that received data


	int sess_state;//SYNSENT, ESTABLISCHED etc
	char conman_state;//'A','D','S', 'B', 'R'; default = '0'.
	int sack_flag;
	int ack_inf_flag;
	int timestamp_flag;
	struct addrid addrid_remove;
	int retransmit_count;//number of retransmissions in 'S' state
	

	unsigned char rex_buf[120];//buffer for retransmissions of SYN/ACK and FIN/ACK signaling headers
	uint16_t rex_buf_len;
	uint16_t rex_ip4_len;

	struct subflow *act_subflow;
	struct subflow *last_subflow;
	
	unsigned char init_top_data[40];//tcp options of SYN packet of first subflow
	uint16_t init_top_len;//length of options

	uint16_t init_window_loc;//window size in initial subflow
	uint16_t curr_window_loc;//current window, scaled
	unsigned char scaling_factor_loc;//window scaling factor in power of 2

	uint16_t init_window_rem;//window size in initial subflow
	uint16_t curr_window_rem;//current window, scaled
	unsigned char scaling_factor_rem;//window scaling factor in power of 2

	uint32_t tsval;//host byte order

	struct timeval teardown_time;
	int teardown_flag;

	UT_hash_handle hh;
};

extern struct session *sess_hash;//defined in sessman

//combined session parms: struct token + fourtuple
// needed to find fourtuple to token
struct session_parms{
	uint32_t token;
	struct fourtuple ft;
	UT_hash_handle hh;
};
extern struct session_parms *sess_parms_hash;//defined in sessman


//tcp option data
struct mptcp_option{
	unsigned char kind;
	unsigned char len;
	unsigned char byte3;
	unsigned char byte4;
	unsigned char data[37];//reserve enough room
}; 
extern struct mptcp_option mptopt[10];//defined in packman


//tcp option data
struct tcp_option{
	unsigned char kind;
	unsigned char len;
	unsigned char data[20];
}; 
extern struct tcp_option topt[20];//defined in packman

//con_man_command: data of command from conman
struct con_man_command{
	char cmd;//L, A, D, S
	int sess;	
	int sfl;
	char ifname[10];
	uint32_t ip_loc;//inet_addr(ipaddress);
	uint32_t ip_rem;//inet_addr(ipaddress);
	uint16_t prt_loc;//inet_addr(ipaddress);
	uint16_t prt_rem;//inet_addr(ipaddress);
};
extern struct con_man_command cmcmd;//defined in conman



//rex_event data: data for tp_events with event_type RETRANSMIT
//tp_events are defined in tp_heap.h
//events handled in sflman
struct rex_event_data{
	int count;
	int tcp_state;
	struct fourtuple ft;
	uint16_t len;//length of buffer
	unsigned char *buf;//data
};


//sess_close_event data: data for tp_events with event_type CLOSE
//tp_events are defined in tp_heap.h
//events handled in sessman
struct sess_close_event_data{
	struct fourtuple ft;//session ft
};

//sfl_close_event data: data for tp_events with event_type CLOSE
//tp_events are defined in tp_heap.h
//events handled in sflman, ft belongs to subflow
struct sfl_close_event_data{
	struct fourtuple ft;//session ft
};


//break_event data: data for tp_events with event_type BREAK
//tp_events are defined in tp_heap.h
//events handled in sessman
struct break_event_data{
	struct fourtuple ft;//session ft
};


//prio_event data: data for tp_events with event_type PRIO
//tp_events are defined in tp_heap.h
//events handled in sflman
struct prio_event_data{
	struct fourtuple ft;//pointing to session
	unsigned char addr_id_loc;//for REMOVE_ADDR
	unsigned char count;
};


//remove_addr_event data: data for tp_events with event_type REMOVE
//tp_events are defined in tp_heap.h
//events handled in sessman
struct remove_addr_event_data{
	uint32_t ipaddr;//andrid to be removed
};



//++++++++++++++++++++++++++++++++++++++++++++++++
//sn smaller
// returns 1 if a "<" b
//++++++++++++++++++++++++++++++++++++++++++++++++
int sn_smaller(uint32_t a, uint32_t b);

//++++++++++++++++++++++++++++++++++++++++++++++++
//sn smaller_equal
// returns 1 if a "<=" b
//++++++++++++++++++++++++++++++++++++++++++++++++
int sn_smaller_equal(uint32_t a, uint32_t b);

//++++++++++++++++++++++++++++++++++++++++++++++++
//translate SM_states
// Prints out a SM state strings to state integers
//++++++++++++++++++++++++++++++++++++++++++++++++
void translate_SM_state(int state_nb, char *state_str);

//++++++++++++++++++++++++++++++++++++++++++++++++
//translate_event_state
//++++++++++++++++++++++++++++++++++++++++++++++++
void translate_event_state(int event_nb, char *state_str);

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_error
// Prints out a string and exits
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_error(char *message, int exit_flag);


//++++++++++++++++++++++++++++++++++++++++++++++++
//print_buffer
// Prints out a string and exits
//++++++++++++++++++++++++++++++++++++++++++++++++
void print_buffer(unsigned char *buf, uint16_t len, int hex_flag);


//++++++++++++++++++++++++++++++++++++++++++++++++
//sprint_buffer
// Prints buffer to string
//++++++++++++++++++++++++++++++++++++++++++++++++
void sprint_buffer(unsigned char *buf_in, char *str_out, uint16_t len, int hex_flag);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void init_msg_data();
// Initializes msg printing
//++++++++++++++++++++++++++++++++++++++++++++++++
void init_msg_data();

//++++++++++++++++++++++++++++++++++++++++++++++++
//void add_msg(char* msg);
//Adds msg to msg array
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_msg(char* msg);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void terminate_msg_data();
// Prints prt_msg_array and closes file
//++++++++++++++++++++++++++++++++++++++++++++++++
void terminate_msg_data();

//++++++++++++++++++++++++++++++++++++++++++++++++
//void init_print_data();
// Initializes data printing
//++++++++++++++++++++++++++++++++++++++++++++++++
void init_print_data();



//++++++++++++++++++++++++++++++++++++++++++++++++
//void load_print_line();
// loads data to packd.print_line
//++++++++++++++++++++++++++++++++++++++++++++++++
void load_print_line(uint32_t id, size_t hook, 
			size_t sess_id, size_t sfl_id, 
			int rex, uint32_t len, unsigned char flags, 
			uint32_t ssn, uint32_t san, uint32_t dsn, uint32_t dan, 
			unsigned char nb_sack_in, uint32_t *sack_in, unsigned char nb_sack_out, uint32_t *sack_out, int verdict);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void load_print_table();
//++++++++++++++++++++++++++++++++++++++++++++++++
void load_print_table(uint32_t id, size_t hook, struct subflow *sfl);


//++++++++++++++++++++++++++++++++++++++++++++++++
//void add_print_data();
// adds a print_line to print_data
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_print_data();

//++++++++++++++++++++++++++++++++++++++++++++++++
//void terminate_print_data();
// Prints print_line_array and closes file
//++++++++++++++++++++++++++++++++++++++++++++++++
void terminate_print_data();



//++++++++++++++++++++++++++++++++++++++++++++++++
//void print_file_line();
// Prints out a bunch of data from packd and packet
//++++++++++++++++++++++++++++++++++++++++++++++++
void print_file_line();


//++++++++++++++++++++++++++++++++++++++++++++++++
//void print_sack(uint32_t *sack, unsigned char nb_sack);
// Prints sack array
//++++++++++++++++++++++++++++++++++++++++++++++++
void print_sack(uint32_t *sack, unsigned char nb_sack);


//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create_key: 
//++++++++++++++++++++++++++++++++++++++++++++++++
uint32_t get_rand();

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create_key: 
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_key(uint32_t *key);


//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create IDSN: 32bit trunc of SHA1(key)
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_idsn_token(uint32_t * const key, uint32_t *idsn, uint32_t *token);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create_mac: 20B mac of keyA + keyB, R_A + R_B
// Input rand_nmb_A,B are in network format
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_mac(uint32_t *keyA, uint32_t *keyB, uint32_t rand_nmb_A, uint32_t rand_nmb_B, uint32_t *mac);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create Token
//++++++++++++++++++++++++++++++++++++++++++++++++
uint32_t create_token(uint32_t idsn);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create ISSN (random number)
//++++++++++++++++++++++++++++++++++++++++++++++++
uint32_t create_issn();

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: convert IP address from uint32_t to char
//  IP address must be in host format
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void printIPaddr(uint32_t ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: convert IP address from uint32_t to char
//  IP address must be in host format
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void sprintIPaddr(char* buf, uint32_t ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: printFourtuple
//++++++++++++++++++++++++++++++++++++++++++++++++
void printFourtuple(struct fourtuple *ft);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: mirrorFourtuple: switches loc and rem
//++++++++++++++++++++++++++++++++++++++++++++++++
void mirrorFourtuple(struct fourtuple *ft);



//HERE COMES EVERYTHING FOR POINTER ARRAY
//++++++++++++++++++++++++++++++++++++++++++++++++
//util: init_pA: Initializes pntArray
//++++++++++++++++++++++++++++++++++++++++++++++++
void init_pA(struct pntArray *pa);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: add_pnt_pA: Adds pointer to pntArray
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_pnt_pA(struct  pntArray *pa, void *pnt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: write_index_pA: Writes to pnt to index in pntArray
//++++++++++++++++++++++++++++++++++++++++++++++++
void write_pnt_pA(struct pntArray *pa, int index, void *pnt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: del_index_pA: Deletes pnt to index in pntArray and puts NULL in the spot
//++++++++++++++++++++++++++++++++++++++++++++++++
void del_index_pA(struct pntArray *pa, int index);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: get_index_pA: Gets index to pnt in pntArray 
// -1 if not found
//++++++++++++++++++++++++++++++++++++++++++++++++
int get_index_pA(struct  pntArray *pa, void *pnt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: get_pnt_pA: Gets pnt to index in anyArray 
// NULL if not found
//++++++++++++++++++++++++++++++++++++++++++++++++
void* get_pnt_pA(struct  pntArray *pa, int index);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: del_pnt_pA: Deletes pnt from pntArray (if present)
//++++++++++++++++++++++++++++++++++++++++++++++++
void del_pnt_pA(struct pntArray *pa, void *pnt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: clear_pA(index_pntArray* pa)
//++++++++++++++++++++++++++++++++++++++++++++++++
void clear_pA(struct  pntArray *pa);

void sprintFourtuple(char* buf, struct fourtuple *ft);
