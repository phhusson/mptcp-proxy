//*****************************************************
//*****************************************************
//
// sessman.c 
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
#include "tp_heap.h"
#include "packman.h"
#include "sflman.h"
#include "sessman.h"
#include "conman.h"
#include "mptcp_proxy.h"
#include "map_table.h"
#include "mangleman.h"


struct dss_option dssopt_in;
struct dss_option dssopt_out;

struct session *sess_hash = NULL;
struct session_parms *sess_parms_hash = NULL;

//++++++++++++++++++++++++++++++++++++++++++++++++
//int create_new_session_input()
//  creates session when hook=1 and TPcap
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_new_session_input(uint32_t *key_rem) {
	char buf_key[32];
	sprint_buffer((unsigned char*) key_rem, buf_key, 8, 1);
	sprintf(msg_buf,"contemplate new sess_input: key_rem=%s,input tcp_seq=%lu, tcp_an=%lu",
		buf_key,
		(long unsigned) ntohl(packd.tcph->th_seq),
		(long unsigned) ntohl(packd.tcph->th_ack));
	add_msg(msg_buf);

	//update mss
	unsigned char init_len = packd.tcplen-20;
	manipulate_mss(packd.buf+packd.pos_thead+20, &init_len);

	unsigned char scaling_factor = find_window_scaling(packd.buf+packd.pos_thead+20, &init_len);
	int timestamp_flag = find_offset_of_tcp_option(packd.buf+packd.pos_thead+20, init_len, 8);

	//create subflow
	// set sess* = NULL since not yet existent.
	// overwrite = 1 in case subflow already exists

	uint32_t token_rem;
	uint32_t idsn_rem;
	create_idsn_token(key_rem, &idsn_rem, &token_rem);

	uint32_t issn_rem = ntohl(packd.tcph->th_seq);
	struct subflow  *sflx;
	sflx = create_subflow(
		 &packd.ft,
		 0,//address id loc
		 0,//address id rem
		 PRE_SYN_REC_1,
		 ACTIVE,
		 0,//loc ISN
		 issn_rem,//rem ISN
		 0,//loc offset
		 idsn_rem - issn_rem,//remot offset
		 0,//random number loc
		 0,//random number rem
		 1);

	if(sflx == NULL) {
		sprintf(msg_buf, "create_new_session_input: returns NULL when creating subflow");
		add_msg(msg_buf);
		return 0;
	}

	struct session* sess;
	sess = create_session(
		&packd.ft,
		0,//key loc
		key_rem,
		0,//IDSNloc
		idsn_rem, //rem IDSN
		0,//Tokenloc
		token_rem, //rem Token
		0,//offset loc
		issn_rem + OFFSET_TCP_SN - idsn_rem,//ensure that tcp_rem = issn_rem
		PRE_SYN_REC_1,
		sflx,
		1);


	if(sess == NULL) {
		sprintf(msg_buf, "create_new_session_input: returns NULL when creating session");
		add_msg(msg_buf);
		return 0;
	}
	

	sflx->sess = sess;
	sflx->highest_sn_rem = issn_rem;


	//packd update
	packd.sfl = sflx;
	packd.sess = sess;
	packd.tcph->th_seq = htonl( packd.sfl->isn_rem + packd.sess->offset_rem + packd.sfl->offset_rem );

	sess->init_window_rem = ntohs(packd.tcph->th_win);
	sess->scaling_factor_rem = scaling_factor;
	sess->curr_window_rem = (sess->init_window_loc)>>scaling_factor;
	if(packd.hook == 2) sess->proxy = 1;
	else sess->proxy = 0;

	sess->timestamp_flag = timestamp_flag;
	if(sess->timestamp_flag) sflx->tsecr = get_timestamp(packd.buf + packd.pos_thead+20, packd.tcplen-20, 1);


	//add or eliminate SACK based on DO_SACK
	int adjust_packet = 0;

	//session sack regulation
	if(DO_SACK) {
		sess->sack_flag = 1;
		if(find_tcp_option(packd.buf+packd.pos_thead+20, init_len, 4)){
			sflx->sack_flag = 1;
		} else{
			sflx->sack_flag = 0;

			//furnish with sack flag for subflow sack support
			if(append_sack(packd.buf+packd.pos_thead+20, &init_len)){
				packd.tcplen += 2;
				packd.pos_pay += 2;
				packd.totlen += 2;
				adjust_packet = 1;
			}
		}
	} else{
		sess->sack_flag = 0;
		sflx->sack_flag = 0;

		//remove sack flag to suppress sack on subflow
		if(eliminate_tcp_option(packd.buf+packd.pos_thead+20, &init_len, 4)){
			packd.tcplen -= 2;
			packd.pos_pay -= 2;
			packd.totlen -= 2;
			adjust_packet = 1;
		}
	}


	if(adjust_packet) {
		packd.mptcp_opt_len = 0;//since option is already attached
		if(!output_data_mptcp()) {
			set_verdict(1,0,0);

			execute_sess_teardown(sess);
			sprintf(msg_buf, "contemplate_new_session_output: output_data_mptcp fails");
			add_msg(msg_buf);
			return 0;
		}
		set_verdict(1,1,1);
	}
	else set_verdict(1,1,0);


	sprintf(msg_buf, "contemplate_new_session: new session created - sess_state = PRE_SYN_REC_1");
	add_msg(msg_buf);

	sprintf(msg_buf, "contemplate new sess_input: isn_loc=%lu, isn_rem=%lu, idsn_loc=%lu, idsn_rem=%lu, tcp_seq=%lu, tcp_an=%lu",
		(long unsigned) packd.sfl->isn_loc, (long unsigned) packd.sfl->isn_rem, 
		(long unsigned) packd.sess->idsn_loc, (long unsigned) packd.sess->idsn_rem,
		(long unsigned) ntohl(packd.tcph->th_seq),
		(long unsigned) ntohl(packd.tcph->th_ack));
	add_msg(msg_buf);


	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//contemplate new session
//++++++++++++++++++++++++++++++++++++++++++++++++
int contemplate_new_session() {
	//OUTPUT: Already checked sess == 0, SYN, !ACK && !MPTCP option
	if(packd.hook == 3) return contemplate_new_session_output();

	if(packd.hook == 2){
			
		if(packd.nb_mptcp_options > 0) return contemplate_new_session_input();
		else return contemplate_new_session_output();
	}

	//INPUT: Already checked SYN, !ACK.
	if(packd.hook == 1 && packd.nb_mptcp_options > 0) return contemplate_new_session_input();

	sprintf(msg_buf, "contemplate_new_session: nb_mptcp_options=%zu, hook=%zu, fwd_type=%zu, no action taken", packd.nb_mptcp_options, packd.hook, packd.fwd_type);
	add_msg(msg_buf);
	set_verdict(1,0,0);	
	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//contemplate new session output
//++++++++++++++++++++++++++++++++++++++++++++++++
int contemplate_new_session_output() {

	packd.fwd_type = T_TO_M;

	//behaves like an output: packet arrives from TCP and is sent to subflow
	packd.ft.ip_loc = ntohl(packd.ip4h->ip_src);
	packd.ft.ip_rem = ntohl(packd.ip4h->ip_dst);
	packd.ft.prt_loc = ntohs(packd.tcph->th_sport);
	packd.ft.prt_rem = ntohs(packd.tcph->th_dport);

	sprintf(msg_buf, "contemplate_new_session_output: input tcp_seq=%lu, tcp_an=%lu",
			(long unsigned) ntohl(packd.tcph->th_seq),
			(long unsigned) ntohl(packd.tcph->th_ack));
	add_msg(msg_buf);


	unsigned char init_len = packd.tcplen-20;
	//unsigned char len = packd.tcplen - 20;

	//find window scale factor
	unsigned char scaling_factor = find_window_scaling(packd.buf+packd.pos_thead+20, &init_len);
	int timestamp_flag = find_offset_of_tcp_option(packd.buf+packd.pos_thead+20, init_len, 8);


	//create TPcap option and append to packd.mptcp_opt_buf (which is still zero)
	//if too long, kill the whole MPTCP idea and fallback to ordinary TCP mode
	uint32_t key_loc[2];
	create_key(key_loc);//create local key

	uint32_t token_loc;
	uint32_t idsn_loc;
	create_idsn_token(key_loc, &idsn_loc, &token_loc);

	uint32_t offset_loc = ntohl(packd.tcph->th_seq) - idsn_loc;//local offset SNtcp - DSN

	if(!create_MPcap(packd.mptcp_opt_buf+packd.mptcp_opt_len, key_loc, NULL) ) {

		sprintf(msg_buf, "contemplate_new_session_output: total option len too long, len=%u", packd.mptcp_opt_len);
		add_msg(msg_buf);	
		return 0;
	}


	//create subflow
	// set sess* = NULL since not yet existent.
	// overwrite = 1 in case subflow already exists
	struct subflow  *sflx;
	uint32_t issn_loc = ntohl(packd.tcph->th_seq) - OFFSET_TCP_SN;

	sflx = create_subflow(
		 &packd.ft,
		 0,//address id loc
		 0,//address id rem
		 SYN_SENT,//tcp_state
		 ACTIVE,//act_state
		 issn_loc,//loc ISSN
		 0,//rem ISSN
		 idsn_loc - issn_loc,//loc offset
		 0,//remote offset
		 0,//random number loc
		 0,//random number rem
		 1);
	if(sflx == NULL) {
		sprintf(msg_buf, "contemplate_new_session_output returns NULL when creating subflow");
		add_msg(msg_buf);
		return 0;
	}

	//create session
	struct session *sess;
	sess = create_session(
		&packd.ft,
		key_loc, //local key
		0, //remote key not yet knwon
	 	idsn_loc, //loc IDSN
		0, //rem IDSN
	 	token_loc, //loc token
		0, //rem token
		offset_loc,
		0, //rem offset
		SYN_SENT,
		sflx,
		1);
	if(sess == NULL) {
		sprintf(msg_buf, "contemplate_new_session_output returns NULL when creating session");
		add_msg(msg_buf);
		return 0;
	}

	struct session_parms *sess_parm;
	sess_parm = create_session_parm(sess->token_loc, &packd.ft, 1);
	if(sess_parm == NULL) {
		sprintf(msg_buf, "contemplate_new_session_output returns NULL when creating session_parm");
		add_msg(msg_buf);
		return 0;
	}


	if(DO_SACK) {
		sflx->sack_flag = 1;
		if(find_tcp_option(packd.buf+packd.pos_thead+20, init_len, 4)){
			sess->sack_flag = 1;
		} else {
			sess->sack_flag = 0;

			//furnish with sack flag for subflow sack support
			if(append_sack(packd.buf+packd.pos_thead+20, &init_len)){
				packd.tcplen += 2;
				packd.pos_pay += 2;
				packd.totlen += 2;
			}
		}
	} else {
		sess->sack_flag = 0;
		sflx->sack_flag = 0;

		//remove sack flag to suppress sack on subflow
		if(eliminate_tcp_option(packd.buf+packd.pos_thead+20, &init_len, 4)) {
			packd.tcplen -= 2;
			packd.pos_pay -= 2;
			packd.totlen -= 2;
		}
	}

	// buffer initial tcp options until the session has been created
	unsigned char init_opt[40];
	memmove(init_opt, packd.buf+packd.pos_thead+20, init_len);

	sess->init_top_len = init_len;//these are buffered inital options
	memmove(sess->init_top_data, init_opt, init_len);//these are the compacted inital options

	sess->init_window_loc = ntohs(packd.tcph->th_win);
	sess->scaling_factor_loc = scaling_factor;
	sess->curr_window_loc = (sess->init_window_loc)>>scaling_factor;
	sess->timestamp_flag = timestamp_flag;
	if(sess->timestamp_flag)
		sess->tsval = get_timestamp(packd.buf + packd.pos_thead+20, packd.tcplen-20, 0);


	sflx->sess = sess;

	//packd update
	packd.sfl = sflx;
	packd.sess = sess;
	packd.tcph->th_seq = htonl( packd.sfl->isn_loc );

	if(!output_data_mptcp()) {
		set_verdict(1,0,0);
		execute_sess_teardown(sess);
		sprintf(msg_buf, "contemplate_new_session_output: output_data_mptcp fails");
		add_msg(msg_buf);
		return 0;
	}

	//buffer packet in case retransmission occurs
	cache_packet_header();

	sprintf(msg_buf, "contemplate_new_session_output: new session created, sess_id=%zu, sess_state=SYN_SENT", packd.sess->index);
	add_msg(msg_buf);
	set_verdict(1,1,1);


	//there is room for opimization: the first subflow does not have to be in IP tables
	//	after SYN/ACK handshake

	sprintf(msg_buf, "contemplate_new_sess_output: isn_loc=%lu, isn_rem=%lu, idsn_loc=%lu, idsn_rem=%lu, sfl_seq=%lu, sfl_an=%lu",
		(long unsigned) packd.sfl->isn_loc, (long unsigned) packd.sfl->isn_rem,
		(long unsigned) packd.sess->idsn_loc, (long unsigned) packd.sess->idsn_rem,
		(long unsigned) ntohl(packd.tcph->th_seq),
		(long unsigned) ntohl(packd.tcph->th_ack));
	add_msg(msg_buf);
	
	return 1;
}//end contemplate_new_session_output



//++++++++++++++++++++++++++++++++++++++++++++++++
//contemplate new session input
//++++++++++++++++++++++++++++++++++++++++++++++++
int contemplate_new_session_input(){

	//get rem IDSN from MPTCP CAP option
	uint32_t key_rem[2];

	if(analyze_MPcap(mptopt, packd.nb_mptcp_options, NULL, key_rem)) {
		if(create_new_session_input(key_rem)) { 
			return 0;
		} else {
			set_verdict(0,0,0);
			return 1;
		}
	}

	unsigned char backup;
	unsigned char addr_id_rem;
	uint32_t rand_nmb;
	uint32_t token;
	if(!analyze_MPjoin_syn(mptopt, packd.nb_mptcp_options, &token, &rand_nmb, &addr_id_rem, &backup)) 
		//TODO: No clue
		return 0;

	struct session *sess;
	struct session_parms *sess_parms = NULL;

	struct session_parms *try_sess_parms, *tmp_sess_parms;

	HASH_ITER(hh, sess_parms_hash, try_sess_parms, tmp_sess_parms) {
		if(try_sess_parms != NULL && try_sess_parms->token == token) {
			sess_parms = try_sess_parms;
			break;
		}
	}	
	//HASH_FIND(hh, sess_parms_hash, &token, sizeof(long unsigned int), sess_parms);	
	if(sess_parms == NULL) {

		char str_tok[16];
		sprint_buffer((unsigned char*) &token, str_tok, 4, 1);
		sprintf(msg_buf, "contemplate_new_session_input: session parameter=%s not found", str_tok);
		add_msg(msg_buf);

		set_verdict(1,0,0);
		return 0;
	}

	HASH_FIND(hh, sess_hash, &sess_parms->ft, sizeof(struct fourtuple), sess);
	if(sess == NULL) {
		sprintf(msg_buf, "contemplate_new_session_input: session not found");
		add_msg(msg_buf);

		set_verdict(1,0,0);
		return 0;
	}

	sprintf(msg_buf, "contemplate_new_session_input: MPjoin received for sess_id=%zu", sess->index);
	add_msg(msg_buf);

	packd.sess = sess;

	if(create_new_subflow_input(packd.sess, addr_id_rem, backup, rand_nmb) ){ 
		set_verdict(0,0,0);//packet has to be terminated here
		return 0;
	} else {
		set_verdict(1,1,0);
		return 1;
	}

}//contemplate_new_session_input




//++++++++++++++++++++++++++++++++++++++++++++++++
//session SYN_SENT
//  Targe states: PRE_EST
//  Currently, we omit simultaneous open
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_syn_sent() {
	//Check for INPUT (or FWD with M_TO_T) + SYN + ACK + MPTCP option
	if(packd.hook < 3 && packd.fwd_type == M_TO_T && packd.syn && packd.ack) {
		//drop session if remote host does not speak MPTCP
		if(packd.nb_mptcp_options == 0) {
			sprintf(msg_buf,"session_syn_sent: no MPTCP options attached. Killing sfl_id=%zu and sess_id=%zu", packd.sfl->index, packd.sess->index);
			add_msg(msg_buf);
			delete_subflow(&packd.ft);
			delete_session_parm(packd.sess->token_loc);
			delete_session(&packd.sess->ft, 1);
			set_verdict(1,0,0);
			return 0;
		}

		//get rem IDSN from MPTCP CAP option
		uint32_t key_rem[2];
		uint32_t key_loc[2];
		if(!analyze_MPcap(mptopt, packd.nb_mptcp_options, key_loc, key_rem)) {
			sprintf(msg_buf, "session_syn_sent: analyze_MPcap fails. Killing sfl_id=%zu and sess_id=%zu", packd.sfl->index, packd.sess->index);
			add_msg(msg_buf);
			delete_subflow(&packd.ft);
			delete_session_parm(packd.sess->token_loc);
			delete_session(&packd.sess->ft, 1);
			set_verdict(1,0,0);
			return 0;
		}

		//add or eliminate SACK based on DO_SACK
		int adjust_packet = 0;

		//check sack support for subflow
		unsigned char len = packd.tcplen-20;
		if(DO_SACK) {

			if(find_tcp_option(packd.buf+packd.pos_thead+20, len, 4)) {
			
				//everything fine; in case sess->sack_flag == 0, simply keep the sack_flag rolling
			} else{

				packd.sfl->sack_flag = 0;//no sfl sack support
				if( packd.sess->sack_flag) {

					//furnish with sack flag for subflow sack support
					if(append_sack(packd.buf+packd.pos_thead+20, &len)){
						packd.tcplen += 2;
						packd.pos_pay += 2;
						packd.totlen += 2;
						adjust_packet = 1;
					}
				}
			}
		} else {
			if(find_tcp_option(packd.buf+packd.pos_thead+20, len, 4)) {
				//ensure no sess->sack support
				if(eliminate_tcp_option(packd.buf+packd.pos_thead+20, &len, 4)){
					packd.tcplen -= 2;
					packd.pos_pay -= 2;
					packd.totlen -= 2;
					adjust_packet = 1;
				}
			} else {
				//everthing fine
			}
		}


		unsigned char init_len = packd.tcplen-20;
		unsigned char scaling_factor = find_window_scaling(packd.buf+packd.pos_thead+20, &init_len);
		packd.sess->init_window_rem = ntohs(packd.tcph->th_win);
		packd.sess->scaling_factor_rem = scaling_factor;
		packd.sess->curr_window_rem = (packd.sess->init_window_loc)>>scaling_factor;


		packd.sess->key_rem[0] = key_rem[0];
		packd.sess->key_rem[1] = key_rem[1];

		create_idsn_token(packd.sess->key_rem, &packd.sess->idsn_rem, &packd.sess->token_rem);


		packd.sess->highest_dsn_rem = packd.sess->idsn_rem+1;
		packd.sess->highest_dan_rem = packd.sess->idsn_rem+1;

		packd.sfl->isn_rem = ntohl(packd.tcph->th_seq);	
		packd.sess->offset_rem = packd.sfl->isn_rem + OFFSET_TCP_SN - packd.sess->idsn_rem;
		packd.sfl->offset_rem = packd.sess->idsn_rem - packd.sfl->isn_rem;



//		enter_dsn_packet(packd.sfl->map_recv, packd.sfl, packd.sess->idsn_rem, packd.sfl->isn_rem, 1);
		packd.sfl->highest_sn_loc += 1;
		packd.sfl->highest_an_loc = packd.sfl->highest_sn_loc;

		//update SN/AN -> DSN/DAN
		packd.tcph->th_seq = htonl( packd.sfl->isn_rem + packd.sess->offset_rem + packd.sfl->offset_rem );
		packd.tcph->th_ack = htonl( packd.sfl->highest_an_loc + packd.sess->offset_loc + packd.sfl->offset_loc );

		packd.sfl->tcp_state = PRE_EST;
		packd.sess->sess_state = PRE_EST;

		if(adjust_packet) {
			packd.mptcp_opt_len = 0;//since option is already attached
			if(!output_data_mptcp()) {
				set_verdict(1,0,0);
				execute_sess_teardown(packd.sess);
				sprintf(msg_buf, "session_syn_sent: output_data_mptcp fails for sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
				add_msg(msg_buf);

				return 0;
			}
			set_verdict(1,1,1);
		}
		else set_verdict(1,1,0);



		sprintf(msg_buf, "syn_sent: isn_loc=%lu, isn_rem=%lu, idsn_loc=%lu, idsn_rem=%lu, tcp_seq=%lu, tcp_an=%lu",
			(long unsigned) packd.sfl->isn_loc, (long unsigned) packd.sfl->isn_rem, 
			(long unsigned) packd.sess->idsn_loc, (long unsigned) packd.sess->idsn_rem,
			(long unsigned) ntohl(packd.tcph->th_seq),
			(long unsigned) ntohl(packd.tcph->th_ack));
		add_msg(msg_buf);

		return 1;
	}

	//consider SYN retransmission
	if(packd.hook > 1 && packd.fwd_type == T_TO_M && packd.syn && !packd.ack) {
		retransmit_cached_packet_header();
		set_verdict(1,1,1);
		//TODO: Confirm return value
		return 0;
	}
	set_verdict(1,0,0);
	return 0;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//session PRE_SYN_REC_1
//  Target states: SYN_REC
//  Add TP_CAP header
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_pre_syn_rec_1() {
	if(!packd.syn || !packd.ack) {
		set_verdict(1,0,0);
		return 0;
	}

	if(packd.hook < 3 && packd.fwd_type == M_TO_T){
		set_verdict(1,0,0);
		//TODO: Confirm return value
		return 0;
	}

	//end to end MPTCP			
	if(packd.hook == 2 && packd.fwd_type == T_TO_M && packd.nb_mptcp_options > 0) {
		delete_subflow(&packd.ft);
		delete_session_parm(packd.sess->token_loc);
		delete_session(&packd.sess->ft, 0);
		set_verdict(1,0,0);
		//TODO: Confirm return value
		return 0;
	}

	packd.sfl = packd.sess->act_subflow;		

	unsigned char init_len = packd.tcplen - 20;
	manipulate_mss(packd.buf+packd.pos_thead+20, &init_len);


	//check sack support for subflow
	if(DO_SACK) {
		if( find_tcp_option(packd.buf+packd.pos_thead+20, init_len, 4)) {
			//everything fine; in case sess->sack_flag == 1, simply keep the sack_flag rolling
		} else {
			packd.sess->sack_flag = 0;//no sfl sack support
			if( packd.sfl->sack_flag) {
				//furnish with sack flag for subflow sack support
				if(append_sack(packd.buf+packd.pos_thead+20, &init_len)) {
					packd.tcplen += 2;
					packd.pos_pay += 2;
					packd.totlen += 2;
				}
			}
		}
	} else {
		if( find_tcp_option(packd.buf+packd.pos_thead+20, init_len, 4)) {
			//ensure no sess->sack support
			if(eliminate_tcp_option(packd.buf+packd.pos_thead+20, &init_len, 4)) {
				packd.tcplen -= 2;
				packd.pos_pay -= 2;
				packd.totlen -= 2;
			}
		}
	}

	//find window scale factor
	unsigned char scaling_factor = find_window_scaling(packd.buf+packd.pos_thead+20, &init_len);
	packd.sess->init_window_loc = ntohs(packd.tcph->th_win);
	packd.sess->scaling_factor_loc = scaling_factor;
	packd.sess->curr_window_loc = packd.sess->init_window_loc>>scaling_factor;

	//buffer initial tcp options until the session has been created
	unsigned char init_opt[40];
	memmove(init_opt, packd.buf+packd.pos_thead+20, init_len);

	//create TPcap option and append to packd.mptcp_opt_buf (which is still zero)
	//if too long, kill the whole MPTCP idea and fallback to ordinary TCP mode
	create_key(packd.sess->key_loc);
	create_idsn_token(packd.sess->key_loc, &packd.sess->idsn_loc, &packd.sess->token_loc);

	packd.sess->offset_loc = ntohl(packd.tcph->th_seq) - packd.sess->idsn_loc;
	packd.sess->highest_dsn_loc = packd.sess->idsn_loc;


	struct session_parms *sess_parm;
	sess_parm = create_session_parm(packd.sess->token_loc, &packd.ft, 1);
	if(sess_parm == NULL){
		sprintf(msg_buf,"session_pre_syn_rec_1 returns NULL when creating session_parm, sess_id=%zu", packd.sess->index);
		add_msg(msg_buf);
	}

	if(!create_MPcap(packd.mptcp_opt_buf+packd.mptcp_opt_len, packd.sess->key_loc, NULL)) {
		sprintf(msg_buf, "session_pre_syn_rec_1: cannot create MPcap since option too long, len=%d, sess_id=%zu", packd.mptcp_opt_len, packd.sess->index);
		add_msg(msg_buf);	
		execute_sess_teardown(packd.sess);
		set_verdict(1,0,0);
		return 0;
	}

	packd.sfl->isn_loc = ntohl(packd.tcph->th_seq) - OFFSET_TCP_SN;//same as tcp sn
	packd.sfl->offset_loc = packd.sess->idsn_loc - packd.sfl->isn_loc;
	packd.sfl->tcp_state = SYN_REC;

	packd.sess->init_top_len = init_len;//these are buffered inital options
	memmove(packd.sess->init_top_data,init_opt, init_len);//these are the compacted inital options

	packd.sess->sess_state = SYN_REC;		

	packd.sfl->highest_sn_loc = ntohl(packd.tcph->th_seq) - packd.sess->offset_loc - packd.sfl->offset_loc;
	packd.sfl->highest_an_loc = packd.sfl->highest_sn_loc;
	packd.sfl->highest_an_rem = ntohl(packd.tcph->th_ack) - packd.sess->offset_rem - packd.sfl->offset_rem; 
	packd.sfl->highest_sn_rem = packd.sfl->highest_an_rem; 

	packd.tcph->th_seq = htonl(packd.sfl->highest_sn_loc);
	packd.tcph->th_ack = htonl(packd.sfl->highest_an_rem);
	

	if(!output_data_mptcp()) {
		set_verdict(1,0,0);
		sprintf(msg_buf, "session_pre_syn_rec_1: output_data_mptcp fails, sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
		add_msg(msg_buf);
		return 0;
	}

	//buffer packet in case retransmission occurs
	cache_packet_header();
	
	packd.sess->sess_state = SYN_REC;
	sprintf(msg_buf, "session_pre_syn_rec_1: PRE_SYN_REC_1 -> SYN_REC for sess_id=%zu", packd.sess->index);
	add_msg(msg_buf);	
	set_verdict(1,1,1);


	sprintf(msg_buf, "pre_syn_rec: isn_loc=%lu, isn_rem=%lu, idsn_loc=%lu, idsn_rem=%lu, sfl_seq=%lu, sfl_an=%lu",
		(long unsigned) packd.sfl->isn_loc, (long unsigned) packd.sfl->isn_rem, 
		(long unsigned) packd.sess->idsn_loc, (long unsigned) packd.sess->idsn_rem,
		(long unsigned) ntohl(packd.tcph->th_seq),
		(long unsigned) ntohl(packd.tcph->th_ack));
	add_msg(msg_buf);

	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//session PRE_EST
//  Target states: ESTABLISHED
//  Add TP_CAP headers with both ISDNs
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_pre_est() {

	if(packd.hook<=1 || packd.fwd_type != T_TO_M || packd.syn || !packd.ack || packd.fin) {
		set_verdict(1,0,0);
		return 0;
	}

	packd.sfl = packd.sess->act_subflow;

	//append IDSNloc and IDSNrem to packd.mptcp_opt_buf (which is still zero)
	//if too long, kill the whole MPTCP idea and fallback to ordinary TCP mode
	if( !create_MPcap(packd.mptcp_opt_buf+packd.mptcp_opt_len, packd.sess->key_loc, packd.sess->key_rem) ){

		sprintf(msg_buf, "session_pre_est: analyze_MPcap fails. Killing sfl_id=%zu and sess_id=%zu", packd.sfl->index, packd.sess->index);
		add_msg(msg_buf);
		delete_subflow(&packd.ft);
		delete_session_parm(packd.sess->token_loc);
		delete_session(&packd.sess->ft, 1);
		set_verdict(1,0,0);
		return 0;
	}

	packd.sess->highest_dsn_loc += 1;
	packd.sess->last_dan_loc = packd.sess->highest_dsn_loc;
	packd.sess->highest_dan_loc = packd.sess->highest_dsn_loc;

	packd.sfl->highest_sn_loc = ntohl(packd.tcph->th_seq) - packd.sess->offset_loc - packd.sfl->offset_loc;
	packd.sfl->highest_an_rem = ntohl(packd.tcph->th_ack) - packd.sess->offset_rem - packd.sfl->offset_rem ;
	packd.sfl->highest_sn_rem = packd.sfl->highest_an_rem;
	packd.sfl->highest_an_loc = packd.sfl->highest_sn_loc;


	packd.tcph->th_seq = htonl(packd.sfl->highest_sn_loc);
	packd.tcph->th_ack = htonl(packd.sfl->highest_an_rem);

	packd.sess->curr_window_loc = ntohs(packd.tcph->th_win);
	packd.sfl->tcp_state = ESTABLISHED;
	packd.sess->sess_state = ESTABLISHED;

	if(!output_data_mptcp()){
		set_verdict(1,0,0);
		sprintf(msg_buf, "session_pre_est: output_data_mptcp fails, sess_id=%zu", packd.sess->index);
		add_msg(msg_buf);
		return 0;
	}

	//buffer packet in case retransmission occurs
	cache_packet_header();

	sprintf(msg_buf, "session_pre_est: PRE_EST->ESTABLISHED - sess->sack=%d, sfl->sack=%d, sess_id=%zu, sfl_id=%zu",
		packd.sess->sack_flag, packd.sfl->sack_flag, packd.sess->index, packd.sfl->index);
	add_msg(msg_buf);
	set_verdict(1,1,1);

	sprintf(msg_buf, "session_pre_est: isn_loc=%u, isn_rem=%u, idsn_loc=%u, idsn_rem=%u, sfl_seq=%u, sfl_an=%u",
		packd.sfl->isn_loc, packd.sfl->isn_rem, 
		packd.sess->idsn_loc, packd.sess->idsn_rem,
		ntohl(packd.tcph->th_seq),
		ntohl(packd.tcph->th_ack));
	add_msg(msg_buf);

	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//session SYN_REC
//  Target states: ESTABLISHED
//  Verify both ISDNs on TP_CAP header
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_syn_rec(){
	if(packd.hook<3 && packd.fwd_type == M_TO_T && !packd.syn && packd.ack && packd.nb_mptcp_options>0){
		//get rem IDSN from MPTCP CAP option
		uint32_t key_rem[2];
		uint32_t key_loc[2];
		if( !analyze_MPcap(mptopt, packd.nb_mptcp_options, key_loc, key_rem) ){
			sprintf(msg_buf, "session_syn_rec: analyze_MPcap fails. Killing sfl_id=%zu and sess_id=%zu!", packd.sfl->index, packd.sess->index);
			add_msg(msg_buf);
			execute_sess_teardown(packd.sess);
			set_verdict(1,0,0);
			return 0;
		}

		if(memcmp(key_loc, packd.sess->key_loc, 8) != 0 || memcmp(key_rem, packd.sess->key_rem, 8) != 0) {
			sprintf(msg_buf, "session_syn_rec: key mismatch! - tearing down sess_id=%zu", packd.sess->index);
			add_msg(msg_buf);

			execute_sess_teardown(packd.sess);
			set_verdict(1,0,0);
			return 0;
		}

		packd.sfl->highest_sn_loc += 1;
		packd.sfl->highest_an_loc = packd.sfl->highest_sn_loc;
		packd.sess->highest_dsn_loc += 1;
		packd.sess->highest_dan_loc = packd.sess->highest_dsn_loc;
		enter_dsn_packet(packd.sfl->map_recv, packd.sfl, packd.sess->idsn_rem, packd.sfl->isn_rem, 1);

		packd.tcph->th_seq = htonl( packd.sfl->highest_sn_rem + packd.sess->offset_rem + packd.sfl->offset_rem );
		packd.tcph->th_ack = htonl( packd.sfl->highest_an_loc + packd.sess->offset_loc + packd.sfl->offset_loc );
		sprintf(msg_buf, "syn_rec: isn_loc=%lu, isn_rem=%lu, idsn_loc=%lu, idsn_rem=%lu, tcp_seq=%lu, tcp_an=%lu",
			(long unsigned) packd.sfl->isn_loc, (long unsigned) packd.sfl->isn_rem, 
			(long unsigned) packd.sess->idsn_loc, (long unsigned) packd.sess->idsn_rem,
			(long unsigned) ntohl(packd.tcph->th_seq),
			(long unsigned) ntohl(packd.tcph->th_ack));
		add_msg(msg_buf);
		packd.sfl->tcp_state = ESTABLISHED;
		packd.sess->sess_state = ESTABLISHED;
		sprintf(msg_buf, "syn_rec: SYN_REC->ESTABLISHED, sess->sack=%d, sfl->sack=%d, sess_id=%zu, sfl_id=%zu", 
			packd.sess->sack_flag, packd.sfl->sack_flag, packd.sess->index, packd.sfl->index);
		add_msg(msg_buf);
		set_verdict(1,1,0);

		return 1;
	}
	//consider SYN retransmission
	if(packd.hook > 1 && packd.fwd_type == T_TO_M && packd.syn && packd.ack){
		retransmit_cached_packet_header();
		set_verdict(1,1,1);
		//TODO: Confirm return value
		return 0;
	}


	set_verdict(1,0,0);
	return 0;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//session ESTABLISHED
//  Target states: PRE_CLOSE_WAIT, FIN_WAIT_1
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_established(){

	//data fin -> FIN_WAIT_1
	if(packd.hook>1 && packd.fwd_type == T_TO_M) {
		if(packd.syn && packd.ack){
			retransmit_cached_packet_header();
			set_verdict(1,1,1);
			//TODO: Confirm return value
			return 0;
		}

		if(dssopt_out.Fflag) {
			packd.sess->fin_dsn_loc = packd.sess->highest_dsn_loc - 1;	
			packd.sess->sess_state = FIN_WAIT_1;
			sprintf(msg_buf, "session_established: ESTABLISHED->FIN_WAIT_1, sess_id=%zu", packd.sess->index );
			add_msg(msg_buf);
			return 1;
		}
	}
	
	//Evaluation of DSS on INPUT
	if(packd.hook<3 && packd.fwd_type == M_TO_T) {
		if(dssopt_in.present == 1) {
			if(dssopt_in.Fflag) {
				packd.sess->fin_dsn_rem = packd.sess->highest_dsn_rem - 1;
				packd.sess->sess_state = PRE_CLOSE_WAIT;
				sprintf(msg_buf, "session_established: ESTABLISHED->PRE_CLOSE_WAIT, sess_id=%zu", packd.sess->index );
				add_msg(msg_buf);
				return 1;
			}
		}
	}

	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//session FIN_WAIT_1
//  Target states: FIN_WAIT_2, PRE_CLOSING, PRE_TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_fin_wait_1() {
	//Evaluation of DSS on INPUT
	if(packd.hook<3 && packd.fwd_type == M_TO_T) {
		//get rem IDSN from MPTCP CAP option
		if( dssopt_in.present == 1) {
			int data_ack = (dssopt_in.Aflag && sn_smaller(packd.sess->fin_dsn_loc, dssopt_in.dan));
			if(data_ack) {
				//terminate_all_subflows(packd.sess);
				if(dssopt_in.Fflag) {
					packd.sess->fin_dsn_rem = packd.sess->highest_dsn_rem - 1;
					packd.sess->sess_state = PRE_TIME_WAIT;
					sprintf(msg_buf, "session_fin_wait_1: FIN_WAIT_1->PRE_TIME_WAIT, sess_id=%zu", packd.sess->index );
					add_msg(msg_buf);
				} else {
					packd.sess->sess_state = FIN_WAIT_2;
					sprintf(msg_buf, "session_fin_wait_1: FIN_WAIT_1->FIN_WAIT_2, sess_id=%zu", packd.sess->index );
					add_msg(msg_buf);
				}
			} else {
				if(dssopt_in.Fflag) {
					packd.sess->fin_dsn_rem = packd.sess->highest_dsn_rem - 1;
					packd.sess->sess_state = PRE_CLOSING;
					sprintf(msg_buf, "session_fin_wait_1: FIN_WAIT_1->PRE_CLOSING, sess_id=%zu", packd.sess->index );
					add_msg(msg_buf);
				}
			}
			return 1;
		}

	}
	return 0;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//session FIN_WAIT_2
//  Target states: PRE_TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_fin_wait_2() {
	//Evaluation of DSS on INPUT
	if(packd.hook<3 && packd.fwd_type == M_TO_T) {
		//get rem IDSN from MPTCP CAP option
		if( dssopt_in.present == 1 ) {
			if(dssopt_in.Fflag) {
				packd.sess->fin_dsn_rem = packd.sess->highest_dsn_rem - 1;
				packd.sess->sess_state = PRE_TIME_WAIT;
				sprintf(msg_buf, "session_fin_wait_2: FIN_WAIT_2->PRE_TIME_WAIT, sess_id=%zu", packd.sess->index );
				add_msg(msg_buf);
				return 1;
			}
		}
	}

	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//session PRE_CLOSE_WAIT
//  Target states: CLOSE WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_pre_close_wait() {
	if(packd.hook>1 && packd.fwd_type == T_TO_M) {
		int data_ack = (packd.ack && sn_smaller(packd.sess->fin_dsn_rem, packd.dan_curr_rem));
		if(data_ack) {
			if(packd.fin==1) {
				packd.sess->fin_dsn_loc = packd.sess->highest_dsn_loc - 1;
				packd.sess->sess_state = LAST_ACK;
				sprintf(msg_buf, "session_pre_close_wait: PRE_CLOSE_WAIT->LAST_ACK, sess_id=%zu", packd.sess->index );
				add_msg(msg_buf);
			} else {
				packd.sess->sess_state = CLOSE_WAIT;
				sprintf(msg_buf, "session_pre_close_wait: PRE_CLOSE_WAIT->CLOSE_WAIT, sess_id=%zu", packd.sess->index );
				add_msg(msg_buf);
			}
	
			return 1;
		} else {
			if(packd.fin==1) {
				packd.sess->fin_dsn_rem = packd.sess->highest_dsn_rem - 1;
				packd.sess->sess_state = PRE_CLOSING;				
				sprintf(msg_buf, "session_pre_close_wait: PRE_CLOSE_WAIT->PRE_CLOSING, sess_id=%zu", packd.sess->index );
				add_msg(msg_buf);	

				return 1;			
			}
		}
	}
	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//session PRE_TIME_WAIT
//  Target states: TIME WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_pre_time_wait(){

	if(packd.hook<=1 || packd.fwd_type != T_TO_M)
		return 0;

	int data_ack = (packd.ack && sn_smaller(packd.sess->fin_dsn_rem, packd.dan_curr_rem));
	if(!data_ack)
		return 0;
	terminate_all_subflows(packd.sess);
	create_sess_close_event(&packd.sess->ft);
	start_sess_teardown_timer(packd.sess);
	packd.sess->sess_state = TIME_WAIT;
	sprintf(msg_buf, "session_pre_time_wait: sess id=%zu entering sess_state TIME_WAIT", packd.sess->index );
	add_msg(msg_buf);	
	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//session PRE_CLOSING
//  Target states: CLOSING
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_pre_closing(){

	if(packd.hook>1 && packd.fwd_type == T_TO_M) {
		int data_ack = (packd.ack && sn_smaller(packd.sess->fin_dsn_rem, packd.dan_curr_rem));
		if(data_ack) {
			packd.sess->sess_state = CLOSING;
			sprintf(msg_buf, "session_pre_closing: sess id=%zu entering PRE_CLOSING->CLOSING", packd.sess->index );
			add_msg(msg_buf);	
			return 1;
		}
	} else {
		int data_ack = (dssopt_in.Aflag && sn_smaller(packd.sess->fin_dsn_loc, dssopt_in.dan));
		if(data_ack) {
			terminate_all_subflows(packd.sess);
			packd.sess->sess_state = PRE_TIME_WAIT;
			sprintf(msg_buf, "session_closing: sess id=%zu entering sess_state PRE_TIME_WAIT", packd.sess->index );
			add_msg(msg_buf);
			return 1;
		}

	}
	return 0;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//session CLOSING
//  Target states: TIME WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_closing() {
	//Evaluation of DSS on INPUT
	if(packd.hook>=3 || packd.fwd_type != M_TO_T)
		return 0;
	if(dssopt_in.present != 1)
		return 0;
	int data_ack = (dssopt_in.Aflag && sn_smaller(packd.sess->fin_dsn_loc, dssopt_in.dan));
	if(!data_ack)
		return 0;

	terminate_all_subflows(packd.sess);
	create_sess_close_event(&packd.sess->ft);
	start_sess_teardown_timer(packd.sess);
	packd.sess->sess_state = TIME_WAIT;
	sprintf(msg_buf, "session_closing: sess id=%zu entering sess_state TIME_WAIT", packd.sess->index);
	add_msg(msg_buf);
	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//session CLOSE_WAIT
//  Target states:LAST ACK
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_close_wait() {
	if(packd.hook<=1 || packd.fwd_type != T_TO_M || !packd.fin)
		return 0;

	packd.sess->sess_state = LAST_ACK;

	sprintf(msg_buf, "session_close_wait: CLOSE_WAIT->LAST_ACK, sess_id=%zu", packd.sess->index );
	add_msg(msg_buf);
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//session LAST_ACK
//  Target states: TIME WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_last_ack() {

	//Evaluation of DSS on INPUT
	if(packd.hook>=3 || packd.fwd_type != M_TO_T )
		return 0;

	if( dssopt_in.present != 1 )
		return 0;

	int data_ack = (dssopt_in.Aflag && sn_smaller(packd.sess->fin_dsn_loc, dssopt_in.dan));
	if(!data_ack)
		return 0;

	terminate_all_subflows(packd.sess);
	sprintf(msg_buf, "session_last_ack: LAST_ACK->TIME_WAIT, sess_id=%zu", packd.sess->index );
	add_msg(msg_buf);
	packd.sess->sess_state = TIME_WAIT;
	create_sess_close_event(&packd.sess->ft);
	start_sess_teardown_timer(packd.sess);

	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//session TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
int session_time_wait() {
	packd.verdict = 0;
	return 1;	
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//terminate all subflows
//++++++++++++++++++++++++++++++++++++++++++++++++
void terminate_all_subflows(struct session *sess) {
	sprintf(msg_buf, "terminate_all_subflows: terminating for sess_id=%zu", sess->index);
	add_msg(msg_buf);
	struct subflow *sfl;
	for(unsigned i=0; i< sess->pA_sflows.number; i++) {
		sfl = (struct subflow*) (*(packd.sess->pA_sflows.pnts + i));

		if(sfl != NULL && sfl->tcp_state <= CLOSE_WAIT) {
			
			sfl->act_state = CANDIDATE;
			terminate_subflow(sess, sfl);
			
		}
	}
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//int check_sess_close_conditions(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
int check_sess_close_conditions(struct session *sess) {
	struct subflow *sfl;
	for(unsigned i=0; i< sess->pA_sflows.number; i++){
		sfl = (struct subflow*) (*(sess->pA_sflows.pnts + i));

		if(sfl != NULL) return 0;
	}
	return 1;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//send_reset_session()
// Sends reset to the TCP mother socket
//++++++++++++++++++++++++++++++++++++++++++++++++
 int send_reset_session(struct session *sess) {
	struct fourtuple* ftmir = malloc(sizeof(struct fourtuple));
	memcpy(ftmir, &sess->ft, sizeof(struct fourtuple));
	mirrorFourtuple(ftmir); 

	return send_reset_fourtuple(ftmir, sess->highest_dsn_rem + sess->offset_rem);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//create session
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
		size_t overwrite) {
		
	static unsigned int index = 0;

	if(sflx == NULL) return NULL;
	struct session *sess;
	HASH_FIND(hh, sess_hash, ft1, sizeof(struct fourtuple), sess);

	if(overwrite == 0 && sess != NULL) return NULL;

	if(sess == NULL) {
		sess = (struct session*) malloc( sizeof(struct session));
		sess->ft = *ft1;
		HASH_ADD(hh, sess_hash, ft, sizeof(struct fourtuple), sess);
	}
	
	if(key_loc != NULL) memcpy(sess->key_loc, key_loc, 8);
	else memset(sess->key_loc, 0, 8);

	if(key_rem != NULL) memcpy(sess->key_rem, key_rem, 8);
	else memset(sess->key_rem, 0, 8);

	sess->idsn_loc = idsn_loc;
	sess->idsn_rem = idsn_rem;
	sess->token_loc = token_loc;
	sess->token_rem = token_rem;
	sess->offset_loc = offset_loc;
	sess->offset_rem = offset_rem;

	sess->index = index;
	index++;

	sess->highest_dsn_loc = idsn_loc;
	sess->highest_dan_loc = idsn_loc;
	sess->last_dan_loc = idsn_loc;
	sess->highest_dsn_rem = idsn_rem;
	sess->highest_dan_rem = idsn_rem;


	sess->cdsn_rem = idsn_rem;
	sess->fin_dsn_loc = 0;
	sess->fin_dsn_rem = 0;
	sess->sess_state = sess_state;

	sess->conman_state = '0';
	sess->sack_flag = DO_SACK;
	sess->ack_inf_flag = 1;
	sess->act_subflow = sflx;
	sess->last_subflow = sflx;
	sess->scaling_factor_loc = 0;
	sess->scaling_factor_rem = 0;

	init_pA(&sess->pA_addrid_loc);//initalize pntArray of subflows
	struct addrid *addrid_loc = malloc(sizeof(struct addrid));
	addrid_loc->addr = ft1->ip_loc;
	addrid_loc->id = 0;
	add_pnt_pA(&sess->pA_addrid_loc, addrid_loc);
	sess->largest_addr_id_loc = 0;

	init_pA(&sess->pA_addrid_rem);//initalize pntArray of subflows
	struct addrid *addrid_rem = malloc(sizeof(struct addrid));
	addrid_rem->addr = ft1->ip_rem;
	addrid_rem->id = 0;
	add_pnt_pA(&sess->pA_addrid_rem, addrid_rem);

	init_pA(&sess->pA_sflows);//initalize pntArray of subflows
	add_pnt_pA(&sess->pA_sflows, sflx);

	init_pA(&sess->pA_sflows_data);//initalize pntArray of subflows that received data

	sess->teardown_flag = 0;

	return sess;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//create session parm
//	overwrite=0: Do not overwrite entry if session already exists or subflow in request=0, return -1, 
//      overwrite=1: Overwrite entry if session already exists and return 0
//++++++++++++++++++++++++++++++++++++++++++++++++
struct session_parms* create_session_parm(
		uint32_t token,
		struct fourtuple *ft1,
		int overwrite) {
		
	struct session_parms *sess_parm;
	HASH_FIND(hh, sess_parms_hash, &token, sizeof(long unsigned int), sess_parm);

	if(overwrite == 0 && sess_parm != NULL)
		return NULL;

	if(sess_parm == NULL) {
		sess_parm = (struct session_parms*) malloc( sizeof(struct session_parms));
		sess_parm->token = token;
		HASH_ADD(hh, sess_parms_hash, token, sizeof(long unsigned int), sess_parm);
	}

	sess_parm->ft = *ft1;
	return sess_parm;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//delete session
//	Returns 0 if delete successful
//	Returns -1 if session not found
//++++++++++++++++++++++++++++++++++++++++++++++++
int delete_session(struct fourtuple *ft1, int rst_sess) {


	struct session *sess;
	HASH_FIND(hh, sess_hash, ft1, sizeof(struct fourtuple), sess);
	if(sess == NULL) return -1;

	if(sess->sess_state < TIME_WAIT && rst_sess) send_reset_session(sess);

	struct subflow *sfl;
	while(sess->pA_sflows.number > 0) {
		sfl = (struct subflow*) sess->pA_sflows.pnts[0];

		delete_subflow(&sfl->ft);//also deletes pnt in pA_sflows
	}
	clear_pA(&sess->pA_sflows);

	subflow_IPtables('D',1,ft1->ip_loc, ft1->prt_loc, ft1->ip_rem, ft1->prt_rem);
	subflow_IPtables('D',2,ft1->ip_loc, ft1->prt_loc, ft1->ip_rem, ft1->prt_rem);
	subflow_IPtables('D',2,ft1->ip_rem, ft1->prt_rem, ft1->ip_loc, ft1->prt_loc);
	subflow_IPtables('D',3,ft1->ip_loc, ft1->prt_loc, ft1->ip_rem, ft1->prt_rem);

	HASH_DEL(sess_hash, sess);

	if(sess != NULL) free(sess);

	clean_aliases(&if_tab1);
	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//delete session parm
//	Returns 0 if delete successful
//	Returns -1 if session not found
//++++++++++++++++++++++++++++++++++++++++++++++++
int delete_session_parm(uint32_t token) {

	struct session_parms *sess_parm;
	HASH_FIND(hh, sess_parms_hash, &token, sizeof(uint32_t), sess_parm);


	if(sess_parm == NULL) return -1;

	HASH_DEL(sess_parms_hash, sess_parm);

	if(sess_parm != NULL) free(sess_parm);
	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//void delete_all_sessions()
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_all_sessions() {
	struct session *curr_sess, *tmp_sess;
	curr_sess = NULL;

	HASH_ITER(hh, sess_hash, curr_sess, tmp_sess) {
		if(curr_sess != NULL){	
	
			delete_session_parm(curr_sess->token_loc);
			delete_session(&curr_sess->ft, 1);
		}
	}
	return;			
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSION: find_subflow_in_session(struct session *sess, int sfl_index_provided, size_t sfl_index, int must_be_cand)
//++++++++++++++++++++++++++++++++++++++++++++++++
struct subflow* find_subflow_in_session(struct session *sess,
		int sfl_index_provided, size_t sfl_index, int must_be_cand) {

	//finds subflow: checks if specified subflow index in cmcmd exists and is found in session, and if it is canddiate
	//	if not, it picks the first candidate it finds.

	struct subflow *sflx = NULL;
	struct subflow *sfly = NULL;

	for(unsigned j1=0; j1<sess->pA_sflows.number; j1++) {
		struct subflow *sfl_curr = (struct subflow*) sess->pA_sflows.pnts[j1];
		if(sfl_curr == NULL)
			continue;

		if( (sfl_curr->index == sfl_index || !sfl_index_provided) 
				&& (sfl_curr->act_state == 0 || !must_be_cand)
				&& sfl_curr->tcp_state >= ESTABLISHED && sfl_curr->tcp_state <= CLOSE_WAIT) {
			sflx = sfl_curr;
			break;
		} else {
			if( sfly == NULL 
					&& (sfl_curr->act_state == 0 || !must_be_cand)
					&& sfl_curr->tcp_state >= ESTABLISHED && sfl_curr->tcp_state <= CLOSE_WAIT) {

				sfly = sfl_curr; 
				/*

				   printf("find_cand_subflow: case 'D': subflow found, sfl-id=%d\n",\
				   ((struct subflow*) sess->pA_sflows.pnts[j1])->index);
				   */
			}  
			/*
			   printf("find_cand_subflow: case 'D': j1=%d, sess-id=%d, sfl-id=%d, act_state=%d\n",\
			   j1, sess->index,\
			   ((struct subflow*) sess->pA_sflows.pnts[j1])->index, \
			   ((struct subflow*) sess->pA_sflows.pnts[j1])->act_state); 
			   */
		}
	}

	if(sflx==NULL){
		sprintf(msg_buf,"find_cand_subflow: sfl_id=%d is no candidate or not in sess_id=%zu", cmcmd.sfl, sess->index);
		add_msg(msg_buf);
		if(sfly==NULL){
			sprintf(msg_buf, "find_subflow_in_session: no sfl found in sess_id=%zu", sess->index);
			add_msg(msg_buf);
			return NULL;
		}
		sflx = sfly;
	}

	//check if interface is up
	char iface[MAX_LENGTH_IFACE_NAME];
	if( find_interface(&if_tab1, iface, sflx->ft.ip_loc) ){
		return sflx;
	} else {
		sprintf(msg_buf, "find_subflow_in_session: found sfl_id=%zu in sess_id =%zu - but interface \"%s\" not active!", sflx->index, sess->index, iface);
		add_msg(msg_buf);
		return NULL;
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//void add_subflow_to_session(struct subflow *sfl, struct session * sess)
//	Returns -1 if session not found
//++++++++++++++++++++++++++++++++++++++++++++++++
inline void add_subflow_to_session(struct subflow *sfl, struct session * sess) {
	sfl->sess = sess;
	add_pnt_pA(&sess->pA_sflows, sfl);
	return;
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: switch_active_sfl: switches subflow based on MP_PRIO message
//	Returns 1 if switch successful
//	Returns 0 if switch not successful
//++++++++++++++++++++++++++++++++++++++++++++++++
int switch_active_sfl(struct session *sess, struct subflow *new_sfl){

	//we already know that new_sfl != NULL and belongs to sess

	if(sess->conman_state != '0'){
		sprintf(msg_buf, "switch_active_sfl: cannot switch since sess id=%zu is not in \"0\" mode", sess->index);
		add_msg(msg_buf);		
		return 0;
	}

	if(sess->act_subflow != new_sfl){

		sess->cdsn_loc = sess->highest_dsn_loc;//when DANloc confirms CDNS, S is turned off
		sess->retransmit_count = 0;
		sess->last_subflow = sess->act_subflow;
		sess->act_subflow = new_sfl;

		sess->last_subflow->act_state = CANDIDATE;
		sess->act_subflow->act_state = ACTIVE;

		sess->act_subflow->offset_loc = sess->highest_dsn_loc - sess->act_subflow->highest_sn_loc;

		sess->conman_state = 'S';
		sess->ack_inf_flag = 0;

		sprintf(msg_buf, "switch_active_sfl: sess id=%zu switched from subflow %zu to subflow %zu", 
				sess->index, sess->last_subflow->index, sess->act_subflow->index);
		add_msg(msg_buf);
	}
	else {
		sprintf(msg_buf, "switch_active_sfl: sess id=%zu, subflow %zu is already active",
			 sess->index, sess->act_subflow->index);
		add_msg(msg_buf);
	}


	return 1;
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: break_active_sfl: make active sfl to last sfl and new_sfl to active sfl
//++++++++++++++++++++++++++++++++++++++++++++++++
void break_active_sfl(struct session *sess, struct subflow *new_sfl) {
	sess->last_subflow = sess->act_subflow;
	sess->last_subflow->act_state = CANDIDATE;
	sess->last_subflow->tcp_state = TIME_WAIT;
	create_sfl_close_event(&sess->last_subflow->ft);

	sess->act_subflow = new_sfl;
	sess->act_subflow->act_state = ACTIVE;
	sess->act_subflow->ack_state = 1;//to ensure that ACKs are sent out

	sess->cdsn_loc = sess->highest_dan_loc-1;

	sess->act_subflow->offset_loc = sess->highest_dsn_loc - sess->act_subflow->highest_sn_loc;

	sprintf(msg_buf, "break_active_sfl: sess id=%lu switched from subflow %zu to subflow %zu", 
			sess->index,
			sess->last_subflow->index, sess->act_subflow->index);
	add_msg(msg_buf);

}


//++++++++++++++++++++++++++++++++++++++++++++++++
//SESSMAN: break_during_switch: if break of last_subflow happens during switch
//forces switch to end by doing cross-subflow retransmission of last_subflow data
//++++++++++++++++++++++++++++++++++++++++++++++++
void break_during_switch(struct session *sess) {
	//last_subflow has not been completed!
	//map everything from last_subflow to act_subflow: leads to non-monotonous mapping

	sess->last_subflow = sess->act_subflow;
	sess->cdsn_loc = sess->highest_dan_loc - 1;
	sess->conman_state = '0';
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//create_break_event: creates event when all subflows are down
//  fourtuple is that of session
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_sess_break_event(struct fourtuple *ft) {
	//create break event data
	struct break_event_data *brk = malloc(sizeof(struct break_event_data));
	brk->ft = *ft;

	//create new tp_event and put packet on retransmit queue
	struct tp_event *evt = malloc( sizeof(struct tp_event) );
	evt->type = SESS_BREAK;
	evt->data = (void*) brk;

	//insert event
	time_t dsec = BREAK_TIME_INTERVAL; 
	insert_event(evt, dsec, 0);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_break_event: executes or terminates break message retransmission 
//	checks if time for teardown has arrived
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_sess_break_event(struct tp_event *evt) {
	struct break_event_data *brk = (struct break_event_data*) evt->data;

	struct session *sess;
	HASH_FIND(hh, sess_hash, &brk->ft, sizeof(struct fourtuple), sess);
	if(sess == NULL) {
		delete_sess_break_event(evt);
		return;	
	}
	if(check_sess_teardown_timer(sess)) {
		execute_sess_teardown(sess);
	} else {
		if(sess->act_subflow->broken && sess->conman_state == 'B') {
			create_sess_break_event(&brk->ft);
		}
	}
	
	delete_sess_break_event(evt);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_break_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_sess_break_event(struct tp_event *evt) {
	struct break_event_data *brk = (struct break_event_data*) evt->data;
	free( brk );
	free( evt );
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//create_sess_close_event: creates event for closing session in TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_sess_close_event(struct fourtuple *ft) {
	//create close event data
	struct sess_close_event_data *cls = malloc(sizeof(struct sess_close_event_data));
	cls->ft = *ft;

	//create new tp_event and put packet on retransmit queue
	struct tp_event *evt = malloc( sizeof(struct tp_event) );
	evt->type = SESS_CLOSE;
	evt->data = (void*) cls;

	//insert event
	time_t dsec = CLOSE_TIME_INTERVAL; 
	insert_event(evt, dsec, 0);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_sess_close_event: executes or terminates close event 
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_sess_close_event(struct tp_event *evt) {
	struct sess_close_event_data *cls = (struct sess_close_event_data*) evt->data;

	struct session *sess;
	HASH_FIND(hh, sess_hash, &cls->ft, sizeof(struct fourtuple), sess);
	if(!sess) {
		delete_sess_close_event(evt);
		return;	
	}

	if(check_sess_close_conditions(sess)) {
		delete_sess_close_event(evt);
		execute_sess_teardown(sess);
	} else {
		time_t dsec = CLOSE_TIME_INTERVAL; 
		insert_event(evt, dsec, 0);
	}
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_sess_close_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_sess_close_event(struct tp_event *evt) {
	struct sess_close_event_data *cls = (struct sess_close_event_data*) evt->data;
	free( cls );
	free( evt );

}

//++++++++++++++++++++++++++++++++++++++++++++++++
//void start_sess_teardown_timer(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
void start_sess_teardown_timer(struct session *sess) {
	if(sess->teardown_flag) return;

	sess->teardown_flag = 1;
	gettimeofday(&sess->teardown_time, NULL);
	sess->teardown_time.tv_sec += SESS_TEARDOWN_TIME_INTERVAL;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//void stop_sess_teardown_timer(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
void stop_sess_teardown_timer(struct session *sess) {
	sess->teardown_flag = 0;
	return;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//int check_sess_teardown_timer(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
int check_sess_teardown_timer(struct session *sess) {
	if(sess->teardown_flag) {
		struct timeval now;
		gettimeofday(&now, NULL);
		if(sess->teardown_time.tv_sec <= now.tv_sec) return 1;
	}
	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//void execute_sess_teardown(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
void execute_sess_teardown(struct session *sess) {
	if(sess == NULL) return;
	sprintf(msg_buf, "execute_sess_teardown: sess_id=%zu is terminated", sess->index);
	add_msg(msg_buf);
	delete_session_parm(sess->token_loc);
	delete_session(&sess->ft, 1);
}

