//*****************************************************
//*****************************************************
//
// conman.h 
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


//needed for connection manager
#define LEN_FIFO_REQ 200
#define LEN_FIFO_RSP 1000
#define LEN_FIFO_WRD 50
#define MAX_FIFO_WRDS 13


//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: init fifos
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void init_fifos();

//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: parse_fifo_command
//  fifo_read: input string
//  len: length of fifo_read
//  response: response string returned
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int parse_fifo_command(char *fifo_read, size_t len, char *response);


//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: check_fifo_msg(): reads from fifo and evaluates message
//	returns message to fifo
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void check_fifo_msg();

//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: attach session data(buf, sess_id)
//  Lists all subflows, fourtuples for all sessions
//  If sess_id = -1, all sessions are listed
//++++++++++++++++++++++++++++++++++++++++++++++++
void attach_session_data(char *resp);

//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: do_fifo_cmd(struct con_man_command *cmcmd): exercises command sent by fifo
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int do_fifo_cmd();


//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: add_sfl_fifo(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
int add_sfl_fifo(struct session *sess);

//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: delete_sfl_fifo(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
int delete_sfl_fifo(struct session *sess);

//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: switch_sfl_fifo(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
int switch_sfl_fifo(struct session *sess);

//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: break_sfl_fifo(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
int break_sfl_fifo(struct session *sess);

//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: check_for_break(char * const ifname, const uint32_t old_ipaddr)
// this is used when ip address is discontinued
//++++++++++++++++++++++++++++++++++++++++++++++++
void check_for_subflow_break(char * const ifname, const uint32_t old_ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: check_for_remote_break(stuct sesssion * const sess, unsigned char addr_id_rem)
// this is used when REMOVE_ADDR is received
//++++++++++++++++++++++++++++++++++++++++++++++++
void check_for_remote_break(struct session * const sess, struct subflow * const sfl_in, unsigned char addr_id_rem);


//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: do_make(char * const ifname, const uint32_t new_ipaddr)
// this is used when new ip address or interface comes up
//++++++++++++++++++++++++++++++++++++++++++++++++
void do_make(char * const ifname, const uint32_t new_ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: do_break_before_make(char * const ifname, const uint32_t old_ipaddr, const uint32_t new_ipaddr)
//++++++++++++++++++++++++++++++++++++++++++++++++
void do_break_before_make(char * const ifname, const uint32_t old_ipaddr, const uint32_t new_ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: do_remove_address(char * const ifname, const uint32_t old_ipaddr, const uint32_t new_ipaddr )
//sends REMOVE_ADDR on active subflow in case candidates use the local IP address that has been deleted
//++++++++++++++++++++++++++++++++++++++++++++++++
void do_remove_address( struct session *sess, const uint32_t old_ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//create_remove_addr_event: creates event to remove address
//  ensures retransmission of REMOVE_ADDR
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_remove_addr_event(const uint32_t ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_remove_addr_event: executes remove_addr message retransmission (REMOVE_ADDR)
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_remove_addr_event(struct tp_event *evt);


//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_remove_addr__event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_remove_addr_event(struct tp_event *evt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//determine fourtuple
//++++++++++++++++++++++++++++++++++++++++++++++++
int determine_fourtuple(struct session *sess, struct fourtuple *ft);

//++++++++++++++++++++++++++++++++++++++++++++++++
//update_default_route: creates new /24 default route based on IP address provided (host format)
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_default_route(uint32_t ip);


//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: auxil_toggle: auxilary function. replaces manual toggle commands
//++++++++++++++++++++++++++++++++++++++++++++++++
void auxil_toggle(char c);


