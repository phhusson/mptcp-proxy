//*****************************************************
//*****************************************************
//
// sessman.h 
// Bump in the stack implemenation of MPTCP
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
//SESSMAN: int create_new_session_input()
//  creates session when hook=1 and TPcap
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int create_new_session_input(uint32_t *key_rem);


//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: contemplate new session 
//  Start states: Subflow not recongized. No session.
//  Target states: SYN_SENT and PRE_SYN_REC_1
//++++++++++++++++++++++++++++++++++++++++++++++++
int contemplate_new_session();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: contemplate new session output 
//++++++++++++++++++++++++++++++++++++++++++++++++
int contemplate_new_session_output();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: contemplate new session input 
//++++++++++++++++++++++++++++++++++++++++++++++++
int contemplate_new_session_input();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process SYN_SENT
//  Target states: PRE_EST
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_syn_sent();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process PRE_SYN_REC_1
//  Target states: SYN_REC
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_pre_syn_rec_1();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process SYN_REC
//  Target states: ESTABLISHED
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_syn_rec();


//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process PRE_EST
//  Target states: ESTABLISHED
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_pre_est();


//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process ESTABLISHED
//  Target states: PRE_CLOSE_WAIT, FIN_WAIT_1
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_established();


//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process FIN_WAIT_1
//  Target states: FIN_WAIT_2, PRE_CLOSING, PRE_TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_fin_wait_1();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process FIN_WAIT_2
//  Target states: PRE_TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_fin_wait_2();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process PRE_TIME_WAIT
//  Target states: TIME WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_pre_time_wait();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process PRE_CLOSING
//  Target states: CLOSING
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_pre_closing();

//++++++++++++++++++++++++++++++++++++++++++++++++
//process CLOSING
//  Target states: TIME WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_closing();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process PRE_CLOSE_WAIT
//  Target states: CLOSE WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_pre_close_wait();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process CLOSE_WAIT
//  Target states:LAST ACK
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_close_wait();

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: process LAST_ACK
//  Target states: TIME WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int session_last_ack();


//++++++++++++++++++++++++++++++++++++++++++++++++
//session TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_time_wait();


//++++++++++++++++++++++++++++++++++++++++++++++++
//terminate all subflows
//++++++++++++++++++++++++++++++++++++++++++++++++
void terminate_all_subflows(struct session *sess);

//++++++++++++++++++++++++++++++++++++++++++++++++
//int check_sess_close_conditions(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
int check_sess_close_conditions(struct session *sess);


//++++++++++++++++++++++++++++++++++++++++++++++++
//send_reset_session()
// Sends reset to the TCP mother socket
//++++++++++++++++++++++++++++++++++++++++++++++++
 int send_reset_session(struct session *sess);


//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN:create session
//	overwrite=0: Do not overwrite entry if session already exists or subflow in request=0, return -1, 
//      overwrite=1: Overwrite entry if session already exists and return 0
//++++++++++++++++++++++++++++++++++++++++++++++++
struct session* create_session(
		struct fourtuple *ft1,
		uint32_t *key_loc, 
		uint32_t *key_rem,
		uint32_t idsn_loc, 
		uint32_t idsn_rem,
		uint32_t token_loc, 
		uint32_t token_rem,
		uint32_t offset_loc,
		uint32_t offset_rem, 
		size_t sess_state,
		struct subflow *sflx,
		size_t overwrite);

//++++++++++++++++++++++++++++++++++++++++++++++++
//create session parm
//	overwrite=0: Do not overwrite entry if session already exists or subflow in request=0, return -1, 
//      overwrite=1: Overwrite entry if session already exists and return 0
//++++++++++++++++++++++++++++++++++++++++++++++++
struct session_parms* create_session_parm(
		uint32_t token,
		struct fourtuple *ft1,
		int overwrite);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void delete_all_sessions()
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_all_sessions();


//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: delete session
//	Returns 0 if delete successful
//	Returns -1 if session not found
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int delete_session(struct fourtuple *ft1, int rst_sess);

//++++++++++++++++++++++++++++++++++++++++++++++++
//delete session parm
//	Returns 0 if delete successful
//	Returns -1 if session not found
//++++++++++++++++++++++++++++++++++++++++++++++++
int delete_session_parm(uint32_t token);

//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: find_subflow_in_session(struct session *sess, int sfl_index_provided, size_t sfl_index, int must_be_cand)
//++++++++++++++++++++++++++++++++++++++++++++++++
struct subflow* find_subflow_in_session(struct session *sess, int sfl_index_provided, size_t sfl_index, int must_be_cand);


//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: void add_subflow_to_session(struct subflow *sfl, struct session * sess)
//	Returns -1 if session not found
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void add_subflow_to_session(struct subflow *sfl, struct session * sess);


//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: switch_active_sfl: switches subflow based on MP_PRIO message
//	Returns 1 if switch successful
//	Returns 0 if switch not successful
//++++++++++++++++++++++++++++++++++++++++++++++++
int switch_active_sfl(struct session *sess, struct subflow *new_sfl);


//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: break_active_sfl: make active sfl to last sfl and new_sfl to active sfl
//++++++++++++++++++++++++++++++++++++++++++++++++
void break_active_sfl(struct session *sess, struct subflow *new_sfl);


//++++++++++++++++++++++++++++++++++++++++++++++++
//create_sess_break_event: creates event when all subflows are down
//  fourtuple is that of session
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_sess_break_event(struct fourtuple *ft);

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_break_event: executes or terminates break event 
//	checks if time for teardown has arrived
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_sess_break_event(struct tp_event *evt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_break_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_sess_break_event(struct tp_event *evt);


//++++++++++++++++++++++++++++++++++++++++++++++++
//create_sess_close_event: creates event for closing session in TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_sess_close_event(struct fourtuple *ft);

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_sess_close_event: executes or terminates close event 
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_sess_close_event(struct tp_event *evt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_sess_close_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_sess_close_event(struct tp_event *evt);


//++++++++++++++++++++++++++++++++++++++++++++++++
//void start_sess_teardown_timer(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
void start_sess_teardown_timer(struct session *sess);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void stop_sess_teardown_timer(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
void stop_sess_teardown_timer(struct session *sess);

//++++++++++++++++++++++++++++++++++++++++++++++++
//int check_sess_teardown_timer(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
int check_sess_teardown_timer(struct session *sess);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void execute_sess_teardown(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
void execute_sess_teardown(struct session *sess);




void break_during_switch(struct session *sess);
