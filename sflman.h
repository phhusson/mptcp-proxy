//*****************************************************
//*****************************************************
//
// sflman.h 
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

struct tp_event;

//++++++++++++++++++++++++++++++++++++++++++++++++
//SUFLOW: int subflow_completed(struct subflow *sfl)
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_completed(struct subflow *sfl);

//++++++++++++++++++++++++++++++++++++++++++++++++
//SUFLOW: initiate_cand_subflow()
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int initiate_cand_subflow(struct session *sess, struct fourtuple *ft, unsigned char backup);


//++++++++++++++++++++++++++++++++++++++++++++++++
//SUFLOW: initiate_cand_subflow()
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int initiate_cand_subflow(struct session *sess, struct fourtuple *ft, unsigned char backup);


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: int create_new_subflow_input()
//  creates new subflow when hook=1 and TPjion
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_new_subflow_input(struct session *sess, unsigned char addr_id_rem, unsigned char backup, uint32_t rand_nmb);


//++++++++++++++++++++++++++++++++++++++++++++++++
//subflow SYN_SENT
//  Target states: ESTABLISHED
//  Expect SYN/ACK with TP_JOIN2, Send ACK
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_syn_sent();

//++++++++++++++++++++++++++++++++++++++++++++++++
//subflow SYN_RECEIVED
//  Target state: ESTABLISHED
//  Expect ACK with TP_JOIN3
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_syn_received();


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_established()
// Start state: ESTABLISHED
// Target states: LAST_ACK
//++++++++++++++++++++++++++++++++++++++++++++++++
 int subflow_established();


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_close_wait()
// Start state: CLOSE_WAIT
// Target states: LAST_ACK
//++++++++++++++++++++++++++++++++++++++++++++++++
 int subflow_close_wait();


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: terminate_subflow()
// Start state: ESTABLISHED
// Target state: FIN_WAIT_1
//++++++++++++++++++++++++++++++++++++++++++++++++
 int terminate_subflow(struct session *sess, struct subflow *sfl);


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_last_ack()
// Start state: LAST_ACK
// Target states: TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
 int subflow_last_ack();



//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_fin_wait_1()
// Start state: FIN_WAIT_1
// Target states: FIN_WAIT_2, CLOSING, TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
 int subflow_fin_wait_1();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_fin_wait_2()
// Start state: FIN_WAIT_2
// Target states: TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
 int subflow_fin_wait_2();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_closing()
// Start state: CLOSING
// Target states: TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
 int subflow_closing();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: send_traffic_ack()
// Sends ack on candidate subflow in parallel to traffic packet on active subflow
// Packet only serves to satisfy subflow SSN/SAN consistency.
// It does carries thruway tcp_options and DAN-DSS (8B)
//++++++++++++++++++++++++++++++++++++++++++++++++
 int send_traffic_ack(struct subflow *sfl);

//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: send_switch_ack()
// Sends ack on sfl with one to two tpprio options
// Currently, we do not care about timestamps 
//++++++++++++++++++++++++++++++++++++++++++++++++
 int send_switch_ack(struct subflow *new_sfl, struct subflow *old_sfl);


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: send_break_ack()
// Sends ack on sfl with tpprio and remove_addr attached
// Currently, we do not care about timestamps 
//++++++++++++++++++++++++++++++++++++++++++++++++
 int send_break_ack(struct subflow *new_sfl, unsigned char addr_id_loc);

//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: check_for_break_session(struct subflow *const sflx)
// this is used when ip address is discontinued
//++++++++++++++++++++++++++++++++++++++++++++++++
int handle_subflow_break(struct subflow *const sflx);

//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: send_reset_subflow()
// Sends sest on subflow specified
//++++++++++++++++++++++++++++++++++++++++++++++++
 int send_reset_subflow(struct subflow *sfl);


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN:create subflow
//	overwrite=0: Do not overwrite entry if subflow already exists and return -1, 
//      overwrite=1: Overwrite entry if subflow already exists and return 0
//++++++++++++++++++++++++++++++++++++++++++++++++
extern struct subflow* create_subflow(struct fourtuple *ft1,
		 unsigned char addr_id_loc,
		 unsigned char addr_id_rem,
		 int tcp_state,
		 int act_state,
		 uint32_t isn_loc,
		 uint32_t isn_rem,
		 uint32_t offset_loc,
		 uint32_t offset_rem,
		 uint32_t rand_nmb_loc,
		 uint32_t rand_nmb_rem,
		 size_t overwrite);

//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: delete subflow: deletes subflow from hashtable, session and memory
//	Returns 0 if delete successful
//	Returns -1 if subflow not found
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int delete_subflow(struct fourtuple *ft1);


//++++++++++++++++++++++++++++++++++++++++++++++++
//create_rex_event: creates event for retransmission of this packet
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_rex_event(struct fourtuple *ft, int tcp_state, unsigned char *buf, uint16_t buf_len);

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_rex_event: executes or terminates retransmission event 
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_rex_event(struct tp_event *evt);


//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_rex_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_rex_event(struct tp_event *evt);


//++++++++++++++++++++++++++++++++++++++++++++++++
//create_sfl_close_event: creates event for closing session in TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_sfl_close_event(struct fourtuple *ft);

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_sfl_close_event: executes or terminates close event 
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_sfl_close_event(struct tp_event *evt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_sfl_close_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_sfl_close_event(struct tp_event *evt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//create_prio_event: creates event for retrnamission of TPPRIO and eventually REMOVE_ADDR
// Used when old subflow broke
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_prio_event(struct fourtuple *ft, unsigned char addr_id_loc);

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_prio_event: executes or terminates prio event 
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_prio_event(struct tp_event *evt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_prio_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_prio_event(struct tp_event *evt);


//++++++++++++++++++++++++++++++++++++++++++++++++
//create_sfl_break_event: creates event when subflow is broken (e.g. local IP address disappeared)
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_sfl_break_event(struct fourtuple *ft);

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_sfl_break_event: executes or terminates break event 
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_sfl_break_event(struct tp_event *evt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_sfl_break_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_sfl_break_event(struct tp_event *evt);


//++++++++++++++++++++++++++++++++++++++++++++++++
//void start_sfl_teardown_timer(struct subflow *sfl)
//++++++++++++++++++++++++++++++++++++++++++++++++
void start_sfl_teardown_timer(struct subflow *sfl);

//++++++++++++++++++++++++++++++++++++++++++++++++
//int check_sfl_teardown_timer(struct subflow *sfl)
//++++++++++++++++++++++++++++++++++++++++++++++++
int check_sfl_teardown_timer(struct subflow *sfl);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void execute_sfl_teardown(struct subflow *sfl)
//++++++++++++++++++++++++++++++++++++++++++++++++
void execute_sfl_teardown(struct subflow *sfl);


