//*****************************************************
//*****************************************************
//
// mangleman.c 
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
#include "mangleman.h"
#include "map_table.h"


//++++++++++++++++++++++++++++++++++++++++++++++++
//set verdict
//  sets verdict, data_update_flag and size_update_flag
//++++++++++++++++++++++++++++++++++++++++++++++++
void set_verdict(size_t verdict, size_t data_update, size_t size_update) {
	packd.verdict = verdict;
	packd.data_update_flag = data_update;
	packd.size_update_flag = size_update;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_reset_output(): Used when application sends reset
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_reset_output() {

	//sess may not be known if RST is self inserted
	if(packd.sess == NULL) {
		set_verdict(1,0,0);
		return;
	}

	if(packd.sess->sess_state == RST_WAIT) {
		set_verdict(0,0,0);
		return;

	}

	//set subflows to TIME_WAIT and send reset on all except active subflow
	struct subflow *sflx;
	for(unsigned i = 0; i<packd.sess->pA_sflows.number; i++) {

		sflx = (struct subflow*) get_pnt_pA(&packd.sess->pA_sflows, i);
		sflx->tcp_state = TIME_WAIT;
		if(sflx != packd.sess->act_subflow) send_reset_subflow(sflx);
	}

	//start connection teardown timer
	start_sess_teardown_timer(packd.sess);
	create_sess_break_event(&packd.ft);

	//if act subflow is presently NULL, go to TIME WAIT and let session fade away
	if(packd.sess->act_subflow == NULL) {
		packd.sess->sess_state = TIME_WAIT;
		return;
	}

	sprintf(msg_buf,"handle_reset_output: Sending MP_RST on sess_id=%zu, sfl_id=%zu", packd.sess->index, packd.sess->act_subflow->index);
	add_msg(msg_buf);

	packd.sfl = packd.sess->act_subflow;
	packd.sfl->tcp_state = TIME_WAIT;
	packd.sess->sess_state = RST_WAIT;

	create_MPreset(packd.mptcp_opt_buf+packd.mptcp_opt_len, packd.sess->key_rem);

	//send packet out
	packd.tcph->th_seq = htonl( packd.sfl->highest_sn_loc );	
	packd.tcph->th_ack = htonl( packd.sfl->highest_an_rem );

	//update IPs and Prts to subflow IP/port
	packd.ip4h->ip_src = htonl( packd.sfl->ft.ip_loc );
	packd.ip4h->ip_dst = htonl( packd.sfl->ft.ip_rem );
	packd.tcph->th_sport = htons( packd.sfl->ft.prt_loc );
	packd.tcph->th_dport = htons( packd.sfl->ft.prt_rem );
	packd.tcph->th_flags &= 251;//removes TCP RST flag ( "-4"
	if(!packd.ack) packd.tcph->th_flags += 16;//we must set the ACK flag here!
	packd.tcph->th_win = packd.sess->curr_window_loc<<packd.sess->scaling_factor_loc;

	if(output_data_mptcp()) {
		set_verdict(1,1,1);
		create_rex_event(&packd.sfl->ft, packd.sfl->tcp_state, packd.new_buf, packd.tcplen + packd.ip4len);
	} else
		set_verdict(1,0,0);

	sprintf(msg_buf,"handle_reset_output: sess id=%zu entering sess_state RST_WAIT", packd.sess->index);
	add_msg(msg_buf);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_data_reset_input(): Used when DSS option on input carries R
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_data_reset_input() {

	//analyze TPreset and check key
	uint32_t key[2];
	analyze_MPreset(mptopt, packd.nb_mptcp_options, key);
	if(memcmp(key, packd.sess->key_loc, 8) != 0) {


		char buf_key1[30];
		char buf_key2[30];
		sprint_buffer((unsigned char *) key, (char*) &buf_key1, 8, 1);
		sprint_buffer((unsigned char *) packd.sess->key_loc, (char*) &buf_key2, 8, 1);
		sprintf(msg_buf, "handle_data_reset_input: key not recongized. found:%s. expected:%s", buf_key1, buf_key2);
		add_msg(msg_buf);

		set_verdict(0,0,0);
		return;
	}


	//send reset on subflow where packet came in
	send_reset_subflow(packd.sfl);

	//create TCP RST on path through
	if(!packd.rst) packd.tcph->th_flags += 4;//turn on RST
	if(packd.ack) packd.tcph->th_flags &= 239;//turn of ACK
	packd.tcph->th_win += 0;//set window = 0

	packd.tcph->th_seq = htonl( packd.sess->highest_dsn_rem + packd.sess->offset_rem );
	packd.tcph->th_ack = 0;

	//update IPs and Prts on packet to TCP IPs and Prts
	packd.ip4h->ip_src = htonl( packd.sess->ft.ip_rem );
	packd.ip4h->ip_dst = htonl( packd.sess->ft.ip_loc );
	packd.tcph->th_sport = htons( packd.sess->ft.prt_rem );
	packd.tcph->th_dport = htons( packd.sess->ft.prt_loc );

	set_verdict(1,1,0);

	sprintf(msg_buf, "handle_data_reset_input: sess_id=%zu terminates after receiving MP RST", packd.sess->index);
	add_msg(msg_buf);

	//delete session
	delete_session_parm(packd.sess->token_loc);
	delete_session(&packd.sess->ft, 1);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_reset_input()
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_reset_input() {
	if(packd.sess == NULL) {
		set_verdict(1,0,0);	
		return;
	}
	if(packd.sess->sess_state == RST_WAIT) {
		sprintf(msg_buf, "handle_reset_input: RST received in RST_WAIT state. Deleting sfl_id=%zu", packd.sfl->index);
		add_msg(msg_buf);	

		if(packd.sfl == packd.sess->act_subflow){

			sprintf(msg_buf, "handle_reset_input: received TCP RST on act sfl_id=%zu, sess in RST_WAIT, tearing down sess_id=%zu", 
				packd.sfl->index, packd.sess->index);
			add_msg(msg_buf);
			delete_session_parm(packd.sess->token_loc);
			delete_session(&packd.sess->ft, 1);
			set_verdict(0,0,0);
		}
		return;		
	}

	if(packd.sfl->tcp_state == TIME_WAIT) {
		sprintf(msg_buf, "handle_reset_input: RST received in TIME_WAIT state. Deleting sfl_id=%zu", packd.sfl->index);
		add_msg(msg_buf);	
		delete_subflow(&packd.sfl->ft);
		set_verdict(0,0,0);	
		return;
	}

	if(packd.sfl->act_state == CANDIDATE) {
		if(packd.sfl == packd.sess->last_subflow){

			packd.sess->ack_inf_flag = 1;
			sprintf(msg_buf, "handle_reset_input: RST received on last_sfl, id=%zu, resetting ack_inf_flag to 1", packd.sfl->index);
			add_msg(msg_buf);
		}


		delete_subflow(&packd.sfl->ft);
		handle_subflow_break(packd.sfl);
		set_verdict(0,0,0);	
		return;		
	}


	//if active subflow: find candidate subflow in ESTABLISHED state that can take over
	if(packd.sfl->act_state == ACTIVE) {

		if(packd.sfl->sess->sess_state < ESTABLISHED){
			execute_sess_teardown(packd.sfl->sess);
			set_verdict(0,0,0);
			return;
		}

		sprintf(msg_buf, "handle_reset_input: active sfl id=%zu receives TCP RST", packd.sfl->index);	
		add_msg(msg_buf);
		strcpy(cmcmd.ifname, "");
		cmcmd.ip_loc = 0;
		break_sfl_fifo(packd.sfl->sess);
	}

	set_verdict(0,0,0);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//update_timestamp()
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_timestamp(){

	uint32_t ts;		
	if(packd.hook > 1 && packd.fwd_type == T_TO_M) {

		ts = get_timestamp(packd.buf+packd.pos_thead+20, packd.tcplen-20, 0);
		if(sn_smaller(packd.sess->tsval, ts)) packd.sess->tsval = ts;
		return;
	}

	if(packd.hook < 3 && packd.fwd_type == M_TO_T) {

		ts = get_timestamp(packd.buf+packd.pos_thead+20, packd.tcplen-20, 0);
		if(sn_smaller(packd.sfl->tsecr, ts)) packd.sfl->tsecr = ts;
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//update_conn_level_data()
//  updates connection level data
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_conn_level_data() {

	packd.sfl = NULL;

	//dan update
	packd.dan_curr_rem = ntohl(packd.tcph->th_ack) - packd.sess->offset_rem;

	dssopt_out.Aflag = packd.ack;
	dssopt_out.Fflag = packd.fin;
	dssopt_out.Rflag = 0;

	if(packd.fin) packd.sess->ack_inf_flag = 0;

	if(packd.ack == 1) {
		dssopt_out.dan = packd.dan_curr_rem;
		if( packd.sess->highest_dan_rem == packd.dan_curr_rem ) {
			packd.dan_rem_state = 0;
		} else {
			if( sn_smaller(packd.sess->highest_dan_rem, packd.dan_curr_rem) ) {
				packd.dan_rem_state = 1;
			} else {
				packd.dan_rem_state = -1;
			}
		}
	}

	parse_compact_copy_TCP_options(packd.buf+packd.pos_thead+20, packd.tcplen-20);

	//extract sack
	packd.nb_sack_in = 0;
	if(packd.sess->sack_flag) extract_sack_blocks(packd.buf + packd.pos_thead + 20, packd.tcplen-20, &packd.nb_sack_in, packd.sack_in, -packd.sess->offset_rem);	
	packd.nb_sack_in++;//to account for the lowest entry which is always there

	//update remote receive window
	if( packd.sess->curr_window_loc < ntohs(packd.tcph->th_win)) packd.sess->curr_window_loc = ntohs(packd.tcph->th_win);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//determine_thruway_subflow(): output packet
//  thruway refers to packet returned to netfilter
// returns thruway_flag
//++++++++++++++++++++++++++++++++++++++++++++++++
void determine_thruway_subflow(){

	//*****DETERMINE SUBFLOW******

	packd.dsn_curr_loc = ntohl(packd.tcph->th_seq) - packd.sess->offset_loc;
	packd.retransmit_flag = 0;
	packd.verdict = (packd.paylen || (packd.sess->sess_state > ESTABLISHED && packd.sess->sess_state < TIME_WAIT))? 1:0;
	if(packd.fin) packd.sess->fin_dsn_loc = packd.dsn_curr_loc + packd.paylen;
	packd.data_update_flag = packd.verdict;


	//determine subflow for thruway based on cdsn_loc (i.e. dsn_switch)
	if(packd.verdict != 1)
		return;

	//set retransmit flag;
	if( sn_smaller( packd.dsn_curr_loc, packd.sess->highest_dsn_loc)) packd.retransmit_flag = 1;

	//determine gap between new packet and highest_dsn_loc
	uint32_t gap = 0;


	//At this point we assume that there is an active subflow
	int update_highest = 0;
	if(!packd.retransmit_flag) {

		packd.sfl = packd.sess->act_subflow;
		packd.paylen_curr = packd.paylen;

		//increase sn/dsn_highest_loc with gap: 
		//  this "reserves" gap-space on this subflow and keeps dsn->ssn mapping monotonous in case of out-of-order arrival
		gap = packd.dsn_curr_loc - packd.sess->highest_dsn_loc;
		update_highest = 1;

	} else {

		//loop through all subflows and find DSN
		struct subflow *sflx, *sfl_temp = NULL;	//sflx is current sfl, sfl_temp is NULL if not found	
		uint32_t ssn_x;
		uint32_t range_x;

		for(unsigned i=0; i<packd.sess->pA_sflows.number; ++i) {
			sflx = (struct subflow*) (*(packd.sess->pA_sflows.pnts + i));
			find_entry_dsn_retransmit(sflx->map_send, packd.dsn_curr_loc, &sfl_temp, &ssn_x, &range_x);
			if(sfl_temp)
				break;
		}

		//find dsn in session send table: If not found, drop packet
		//find_entry_dsn_retransmit(packd.sess->map_send, packd.dsn_curr_loc, &sfl_temp, &ssn_x, &range_x);

		//sfl was found
		if(sfl_temp) {

			//check if subflow really exists
			struct subflow_pnt *sfl_pnt;
			HASH_FIND(hh, sfl_pnt_hash, &sfl_temp, sizeof(struct subflow_pnt*), sfl_pnt);
			if(sfl_pnt != NULL && sfl_temp->tcp_state == ESTABLISHED) {//ship on old subflow

				packd.sfl = sfl_temp;
				if(packd.sfl->broken) {

					set_verdict(0,0,0);
					return;
				}

				packd.ssn_curr_loc = ssn_x;

				//in case paylen has to be reduced
				packd.paylen_curr = packd.paylen;
				if( range_x < (uint32_t) packd.paylen )
					packd.paylen_curr = (uint16_t) range_x;

			} else {
				sfl_temp = NULL;
			}
		}
		if(!sfl_temp) {//if subflow not found, ship it on active subflow

			packd.sfl = packd.sess->act_subflow;

			if(packd.sfl == NULL || packd.sfl->broken){

				set_verdict(0,0,0);
				return;
			}

			packd.paylen_curr = packd.paylen;
			gap = 0;
			update_highest = 1;
		}
	}//end if(!retransmitflag)

	if(update_highest) {

		packd.ssn_curr_loc = packd.sfl->highest_sn_loc + gap;

		uint32_t dsn = packd.sess->highest_dsn_loc;
		if(packd.retransmit_flag) dsn = packd.dsn_curr_loc;

		//enter packet into session map
		// reserve entire range from last highest to new highest, i.e. including gap	
		enter_dsn_packet_on_top(
			packd.sfl->map_send, 
			packd.sfl,
			dsn,//packd.sess->highest_dsn_loc, 
			packd.sfl->highest_sn_loc,
			packd.paylen + gap);

		delete_below_dsn(packd.sfl->map_send,
			packd.sfl->map_send->top->dsn +packd.sfl->map_send->top->range - 1\
			- (packd.sess->curr_window_rem<<packd.sess->scaling_factor_rem) );


		//update sn/dsn_highest_loc
		//Note: FIN byte enters highest_dsn_loc but not highest_sn_loc
		packd.sfl->highest_sn_loc = packd.ssn_curr_loc + packd.paylen_curr;
		if( sn_smaller(packd.sess->highest_dsn_loc, packd.dsn_curr_loc + packd.paylen_curr + packd.fin )) \
				packd.sess->highest_dsn_loc = packd.dsn_curr_loc + packd.paylen_curr + packd.fin;//may not be the case for cross-sfl retransmissions
	}


	packd.sfl->offset_loc = packd.dsn_curr_loc - packd.ssn_curr_loc;
}			
			

//++++++++++++++++++++++++++++++++++++++++++++++++
//void find_side_acks()
//++++++++++++++++++++++++++++++++++++++++++++++++
void find_side_acks() {

	packd.sess->pA_sflows_data.number = 0;//reset pointer array

	struct subflow *sfl_ack;	
	int outcome;

	packd.sack_in[1] = packd.dan_curr_rem-1;

	if(packd.dan_rem_state==1) packd.sess->highest_dan_rem = packd.dan_curr_rem;

	//update SAN on all subflows that have sent packets
	// and add to pA_sflows_data
	for(unsigned i=0; i< packd.sess->pA_sflows.number; i++) {

		sfl_ack = (struct subflow*) (*(packd.sess->pA_sflows.pnts + i));
		
		if(sfl_ack != NULL &&  !sfl_ack->broken && sfl_ack->tcp_state >= ESTABLISHED &&
				(sfl_ack->tcp_state <= CLOSE_WAIT || packd.sess->sess_state > ESTABLISHED) ) {

			if(sfl_ack->map_recv->bot) packd.sack_in[0] = sfl_ack->map_recv->bot->dsn;
			else packd.sack_in[0] = packd.sack_in[1];

			outcome = 1;
			sfl_ack->sack_sfl_start = 1;
			if(project_sack_space( sfl_ack->map_recv, packd.nb_sack_in, packd.sack_in,
						(int*)&sfl_ack->nb_sack_sfl, sfl_ack->sack_sfl, sfl_ack->highest_an_rem-1, 1)) {

				//check if SSN space is contiguous
				if(sn_smaller_equal(sfl_ack->sack_sfl[0], sfl_ack->highest_an_rem)) {

					sfl_ack->curr_an_rem = sfl_ack->sack_sfl[1]+1;
					
					//SAN proceeded 
					if(sn_smaller(sfl_ack->highest_an_rem, sfl_ack->curr_an_rem)) {

						outcome = 2;
						sfl_ack->last_an_rem = sfl_ack->highest_an_rem;//buffer old an_rem
						sfl_ack->highest_an_rem = sfl_ack->curr_an_rem;//does not include SACK!
					
					}
					sfl_ack->sack_sfl_start = 1;

				} else {//SSN space not contiguous

					sfl_ack->curr_an_rem = sfl_ack->highest_an_rem;
					sfl_ack->sack_sfl_start = 0;//first entry in sack_sfl is already a sack entry
				}

			} else {//not mapping found
				outcome = -1;
				sfl_ack->curr_an_rem = sfl_ack->highest_an_rem;
			}

			if(sn_smaller(sfl_ack->highest_sn_rem, sfl_ack->highest_an_rem)) {

				sfl_ack->highest_an_rem = sfl_ack->highest_sn_rem;

			}

			//SAN hits gap, SAN is old or SAN is forced (ack_state == 1)
			if(outcome == 2 || sfl_ack->ack_state) {
				add_pnt_pA(&packd.sess->pA_sflows_data, sfl_ack);
				sfl_ack->ack_state = 0;
			}

		}
	}
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//int update_thruway(): Only if verdict == 0
//  returns 0 if packet terminates here
//  if the thruway does not hold a payload packet, a side ack is sent on the thruway
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_thruway_subflow() {

	//create a thruway in case there is no FIN and no payload; if not possible drop packet
	
	if(packd.sess->pA_sflows_data.number == 0) {
		packd.sfl = packd.sess->act_subflow;
		packd.sfl->ack_state = 0;

		if(packd.sfl->broken) {
			set_verdict(0,0,0);
			return;
		}		
		packd.ssn_curr_loc = packd.sfl->highest_sn_loc;
		packd.verdict = 1;//update
	} else {//put the first side ACK onto thruway

		packd.sfl = (struct subflow*) (*(packd.sess->pA_sflows_data.pnts));
		packd.ssn_curr_loc = packd.sfl->highest_sn_loc;
		packd.verdict = 1;//update
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//send_side_acks()
//++++++++++++++++++++++++++++++++++++++++++++++++
void send_side_acks() {

	//send acks on the various subflows, except main subflow
	dssopt_out.Mflag = 0;

	//first we have to copy the tcp option header of the packet
	if(! prepare_top_side_ack()) return;
	
	struct subflow *sfl_ack;
	for(unsigned i=0; i<packd.sess->pA_sflows_data.number; i++) {

		sfl_ack = (struct subflow*) (*(packd.sess->pA_sflows_data.pnts + i));
		if( sfl_ack != packd.sfl ) {
			send_traffic_ack(sfl_ack);

			if(PRINT_FILE) load_print_line(packd.id, packd.hook, packd.sess->index, sfl_ack->index, 
				0, 0, 16, 
				sfl_ack->highest_sn_loc - sfl_ack->isn_loc, sfl_ack->curr_an_rem - sfl_ack->isn_rem, 
				packd.dsn_curr_loc - packd.sess->idsn_loc, packd.dan_curr_rem-  packd.sess->idsn_rem, 
				0, packd.sack_in, 0, packd.sack_in, 1);

		}
	}
	packd.mptcp_opt_len = 0;//reset for DSS to be sent on truway
	return;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//set_dss_and_prio()
//++++++++++++++++++++++++++++++++++++++++++++++++
void set_dss_and_prio() {

	//*****THRUWAY MANAGEMENT: ADD DSN + MP_PRIO******
	
	int demand_dss = (packd.paylen > 0 || packd.fin == 1 || packd.sess->sess_state > ESTABLISHED || packd.ack == 1)? 18:0;

	//check if enough room
	if( demand_dss + packd.tcp_opt_len > 40 ) {

		//erase some tcp options here!!!
		//to be done later
		//currently assume there is always enough space
	}

	packd.mptcp_opt_appended = 0;
	if(demand_dss>0) {
	
		dssopt_out.present = 1;
		dssopt_out.Mflag = 0;

		if(packd.paylen > 0 || dssopt_out.Fflag) {
			dssopt_out.Mflag = 1;//do we need this or only when data are present
			dssopt_out.range = packd.paylen + dssopt_out.Fflag;
			dssopt_out.dsn = packd.dsn_curr_loc;
			if(packd.paylen == 0 && dssopt_out.Fflag) dssopt_out.ssn = 0;
			else dssopt_out.ssn = packd.ssn_curr_loc - packd.sfl->isn_loc;
		}

		create_complete_MPdss(packd.mptcp_opt_buf+packd.mptcp_opt_len);
		packd.mptcp_opt_appended = 1;
	}

	//append options to buffer
	set_verdict(1,1,0);

}//end set_dss_and_prio()


//++++++++++++++++++++++++++++++++++++++++++++++++
//update_packet_output()
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_packet_output() {

	packd.tcph->th_seq = htonl( packd.ssn_curr_loc );	

	//Always send ACK
	//Reduce curr_an_rem by 1 if this is an old DAN held on the packet
	packd.san_curr_rem = packd.sfl->curr_an_rem;
	packd.tcph->th_ack = htonl( packd.san_curr_rem );

	//Ensure that SFL ACK flag is always set
	if(!packd.ack) packd.tcph->th_flags += 16;

	//remove fin
	if(packd.fin && dssopt_out.Fflag) packd.tcph->th_flags -= 1;

	//update IPs and Prts to subflow IP/port
	packd.ip4h->ip_src = htonl( packd.sfl->ft.ip_loc );
	packd.ip4h->ip_dst = htonl( packd.sfl->ft.ip_rem );
	packd.tcph->th_sport = htons( packd.sfl->ft.prt_loc );
	packd.tcph->th_dport = htons( packd.sfl->ft.prt_rem );

	unsigned char nb_sacks = packd.sfl->nb_sack_sfl - packd.sfl->sack_sfl_start;
	if(packd.sfl->nb_sack_sfl == 0 || !packd.sfl->sack_flag) nb_sacks = 0;

	uint16_t max_tcp_opt_len = 40; 
	if(packd.mptcp_opt_appended == 1) max_tcp_opt_len -= packd.mptcp_opt_len;

	uint16_t new_tcp_opt_len = packd.tcp_opt_len;

	update_sack_blocks(nb_sacks, packd.sfl->sack_sfl + (packd.sfl->sack_sfl_start<<1), packd.tcp_opt_buf, &new_tcp_opt_len, max_tcp_opt_len, 0);


	if(new_tcp_opt_len != packd.tcp_opt_len) {
		set_verdict(1,1,1);
		packd.tcp_opt_len = new_tcp_opt_len;
	}


	if(packd.mptcp_opt_appended == 1) {

		if(output_data_mptcp()) set_verdict(1,1,1);
	}



	if(PRINT_FILE) {

		int k;
		for(k=0;k<6;k++) {
			packd.sack_in[k] -= packd.sess->idsn_rem;
			packd.sfl->sack_sfl[k] -= packd.sfl->isn_rem;
		}

		load_print_line(packd.id, packd.hook, packd.sess->index, packd.sfl->index, 
		packd.retransmit_flag, packd.paylen, packd.tcph->th_flags, 
		packd.ssn_curr_loc - packd.sfl->isn_loc, packd.san_curr_rem - packd.sfl->isn_rem, 
		packd.dsn_curr_loc - packd.sess->idsn_loc, packd.dan_curr_rem -  packd.sess->idsn_rem, 
		packd.nb_sack_in-1, packd.sack_in+2,
		packd.sfl->nb_sack_sfl - packd.sfl->sack_sfl_start, packd.sfl->sack_sfl + (packd.sfl->sack_sfl_start<<1),
		1 );

		if(PRINT_TABLE) load_print_table(packd.id, packd.hook, packd.sfl);
	}
}//end update_packet
	

//++++++++++++++++++++++++++++++++++++++++++++++++
//update_subflow_level_data()
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_subflow_level_data() {


	//update remote receive window
	if(packd.sess->curr_window_rem < ntohs(packd.tcph->th_win)) packd.sess->curr_window_rem = ntohs(packd.tcph->th_win);

	//update highest_an_loc (do we need that?)
	packd.ssn_curr_rem = ntohl(packd.tcph->th_seq);
	if( packd.paylen+packd.fin > 0 && sn_smaller( packd.sfl->highest_sn_rem, packd.ssn_curr_rem+packd.paylen+packd.fin ) ) 
			packd.sfl->highest_sn_rem = packd.ssn_curr_rem+packd.paylen+packd.fin; 

	parse_compact_copy_TCP_options(packd.buf+packd.pos_thead+20, packd.tcplen-20);

	packd.san_curr_loc = ntohl(packd.tcph->th_ack);//which may be zero
	if(packd.ack != 1)
		return;

	//extract sack
	packd.nb_sack_in = 0;
	if(packd.sfl->sack_flag) extract_sack_blocks(packd.buf + packd.pos_thead + 20, packd.tcplen-20, &packd.nb_sack_in, packd.sack_in, 0);	
	packd.nb_sack_in++;//to account for the lowest entry which is always there


	packd.sack_in[0] = packd.sfl->isn_loc;
	packd.sack_in[1] = packd.san_curr_loc-1;

	project_sack_space( packd.sfl->map_send, packd.nb_sack_in, packd.sack_in,
			(int*)&packd.nb_sack_tcp, packd.sack_tcp, packd.sess->highest_dan_loc-1, 0);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//process_dss() 
//++++++++++++++++++++++++++++++++++++++++++++++++
void process_dss() {

	dssopt_in.present = analyze_MPdss(mptopt, packd.nb_mptcp_options);

	packd.dan_curr_loc = 0;
	if(dssopt_in.present) {

		if( (dssopt_in.Mflag == 1 && packd.paylen > 0) || dssopt_in.Fflag) {

			if(dssopt_in.Fflag) {
				packd.sess->ack_inf_flag = 0;
			}

			//enter packet into sfl ssn table
			//Note: FIN byte does not go into table
			enter_dsn_packet(packd.sfl->map_recv, packd.sfl,
				dssopt_in.dsn, dssopt_in.ssn + packd.sfl->isn_rem, dssopt_in.range - dssopt_in.Fflag);

			//update bottom of table
			//ATTENTION: permitting table size 4X window scaling factor (...+2)
			delete_below_dsn(packd.sfl->map_recv,
				packd.sfl->map_recv->top->dsn + packd.sfl->map_recv->top->range
				- (packd.sess->curr_window_loc<<(packd.sess->scaling_factor_loc+2)) );

			//update highest_dsn_rem if applicable
			//Note: highest_dsn_rem includes FIN byte
			if( sn_smaller(packd.sess->highest_dsn_rem, dssopt_in.dsn + dssopt_in.range) )
				packd.sess->highest_dsn_rem = dssopt_in.dsn + dssopt_in.range;

		}

		//uint32_t dan_loc = packd.sess->highest_dan_loc;//buffer dan_loc
		if( dssopt_in.Aflag == 1) {

			//update highest_dan_loc: if it has increased, verdict MUST be 1
			if( sn_smaller(packd.sess->highest_dan_loc, dssopt_in.dan)) { 
				packd.sess->last_dan_loc = packd.sess->highest_dan_loc;
				packd.sess->highest_dan_loc = dssopt_in.dan;
				
			}
			packd.verdict = 1;
			packd.dan_curr_loc = dssopt_in.dan;

			//check if conman_state can be reset: 
			//This requires that DANloc received on the active subflow is larger than CDSNloc

			if(packd.sess->conman_state == 'S' && sn_smaller_equal(packd.sess->cdsn_loc, packd.sess->highest_dan_loc)) {
				packd.sess->conman_state = '0';
				packd.sess->ack_inf_flag = 1;

				sprintf(msg_buf, "process_dss: reset conman state and ack_inf_flag for sess_id=%zu", packd.sess->index);
				add_msg(msg_buf);

			}

		}
	}//end analyzze Tpdss

	//inc nb_packets for subflow if this is a new transmission on this subflow
	uint16_t load = packd.paylen + (dssopt_in.present && dssopt_in.Fflag) + packd.fin;
	if( load > 0 &&  sn_smaller_equal(packd.ssn_curr_rem + load, packd.sfl->highest_an_rem) ) {
		//ack_state = 1: this means that this subflow needs to be acked
		packd.sfl->ack_state = 1;
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//process_remove_addr() 
//++++++++++++++++++++++++++++++++++++++++++++++++
void process_remove_addr() {
	unsigned char addr_id_rem;
	if(analyze_MPremove_addr(mptopt, packd.nb_mptcp_options, &addr_id_rem) ) {

		sprintf(msg_buf, "process_remove_addr: addr_id_rem=%u, sess_id=%zu", addr_id_rem, packd.sess->index);
		add_msg(msg_buf);

		check_for_remote_break(packd.sess, packd.sfl, addr_id_rem);
		set_verdict(0,0,0);
	}
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//process_prio() 
//++++++++++++++++++++++++++++++++++++++++++++++++
void process_prio(){
	unsigned char *backup = malloc(sizeof(unsigned char));
	*backup = 1;
	unsigned char *addr_id_rem = malloc(sizeof(unsigned char));
	int ret = analyze_MPprio(mptopt, packd.nb_mptcp_options, addr_id_rem, backup);
	if(ret > 0) {

		//we currently only consider switch with backup = 0.

		sprintf(msg_buf,"process_prio: MPprio found in sess_id=%zu, sfl_id=%zu, backup=%u", packd.sess->index, packd.sfl->index, *backup);
		add_msg(msg_buf);
		if(*backup == 0 && packd.sfl != packd.sess->act_subflow) {

			switch_active_sfl(packd.sess, packd.sfl);

		}
		set_verdict(0,0,0);
	}
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//update_packet_input()
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_packet_input() {

	//Define DSNrem
	if(packd.paylen > 0) {

		//find DSN based on SSN on packet
		if( find_DSN(&packd.dsn_curr_rem, packd.sfl->map_recv, packd.ssn_curr_rem ) == 0 ) {

			//THIS SHOULDN"T HAPPEN
			if(dssopt_in.present) {
				//enter packet into table
				enter_dsn_packet(packd.sfl->map_recv, packd.sfl,
					dssopt_in.dsn, dssopt_in.ssn + packd.sfl->isn_rem, dssopt_in.range - dssopt_in.Fflag);

				if( find_DSN(&packd.dsn_curr_rem, packd.sfl->map_recv, packd.ssn_curr_rem ) == 0 ) {
					sprintf(msg_buf, "update_packet_input: DSN not found. sess_id=%zu, sfl_id=%zu, ssn_curr_rem=%lu", 
						packd.sess->index, packd.sfl->index, (long unsigned int) packd.ssn_curr_rem);
					add_msg(msg_buf);
					set_verdict(0,0,0);
					return;
				}
			}
		}

		packd.verdict = 1;

	}
	else {//must be ACK
		
		packd.dsn_curr_rem = packd.sess->highest_dsn_rem;
		if(dssopt_in.Fflag) packd.dsn_curr_rem = dssopt_in.dsn;
	}

	//dan_curr_loc was provided by DAN on DSS.
	//What do do if no DAN in DSS option?
	if(packd.dan_curr_loc == 0) {
		if(packd.ack) packd.dan_curr_loc = packd.sess->highest_dan_loc;
	}
	packd.tcph->th_seq = htonl( packd.dsn_curr_rem + packd.sess->offset_rem );

	//adjust fin
	//TODO: if/else odereing ?
	if(dssopt_in.present && dssopt_in.Fflag) {
	       	if(!packd.fin) packd.tcph->th_flags += 1;//add FIN if not set
	} else {
	       	if(packd.fin) packd.tcph->th_flags -= 1;//remove FIN if set;
	}


	set_verdict(1,1,0);
	unsigned char start_index;
	if(packd.ack == 1) {

		if(packd.sess->ack_inf_flag) {


			//start_index: 0 means sack_tcp[0-1] has gap to largest tcp ack and becomes sack block
			start_index = ( packd.nb_sack_tcp > 0 && sn_smaller(packd.sess->highest_dan_loc, packd.sack_tcp[0] ))? 0:1;
			

			uint32_t dan;
			if( start_index == 0 || packd.nb_sack_tcp == 0) dan = packd.sess->highest_dan_loc;
			else {

				if(sn_smaller(packd.sack_tcp[1] + 1, packd.sess->highest_dan_loc)) dan = packd.sess->highest_dan_loc;
				else {
					dan = packd.sack_tcp[1] + 1;
					packd.sess->highest_dan_loc = dan;//dan inference
				}
			}	

			packd.tcph->th_ack = htonl( dan + packd.sess->offset_loc);
			if(packd.nb_sack_tcp > 1 || (start_index == 0 && packd.nb_sack_tcp == 1) ) {
				
				//parse_compact_copy_TCP_options(packd.buf+packd.pos_thead+20, packd.tcplen-20);
				uint16_t new_tcp_opt_len = packd.tcp_opt_len;
				update_sack_blocks(packd.nb_sack_tcp - start_index, packd.sack_tcp + (start_index<<1), \
								packd.tcp_opt_buf, &new_tcp_opt_len, 40, packd.sess->offset_loc);
				set_verdict(1,1,1);
				
				if(new_tcp_opt_len != packd.tcp_opt_len) {

					packd.tcp_opt_len = new_tcp_opt_len;
				}
				
				//create new packet from old packet and appended options
				packd.tcp_opt_len = pad_options_buffer(packd.tcp_opt_buf, packd.tcp_opt_len);
				create_new_packet(packd.tcp_opt_buf, packd.tcp_opt_len);
			}
		} else {
			packd.tcph->th_ack = htonl( packd.dan_curr_loc + packd.sess->offset_loc);
		}	
	}

	//update IPs and Prts on packet to TCP IPs and Prts
	packd.ip4h->ip_src = htonl( packd.sess->ft.ip_rem );
	packd.ip4h->ip_dst = htonl( packd.sess->ft.ip_loc );
	packd.tcph->th_sport = htons( packd.sess->ft.prt_rem );
	packd.tcph->th_dport = htons( packd.sess->ft.prt_loc );


	if(PRINT_FILE) {


		int k;
		for(k=0;k<6;k++) {
			packd.sack_in[k] -= packd.sfl->isn_loc;
			packd.sack_tcp[k] -= packd.sess->idsn_loc;
		}

		unsigned char nb_sack_out = packd.nb_sack_tcp;
		if(nb_sack_out > 0) nb_sack_out -= start_index;

		load_print_line(packd.id, packd.hook, packd.sess->index, packd.sfl->index, 
			packd.retransmit_flag, packd.paylen, packd.tcph->th_flags, 
			packd.ssn_curr_rem - packd.sfl->isn_rem, packd.san_curr_loc - packd.sfl->isn_loc, 
			packd.dsn_curr_rem - packd.sess->idsn_rem, ntohl(packd.tcph->th_ack) -  packd.sess->idsn_loc - packd.sess->offset_loc, 
			packd.nb_sack_in-1, packd.sack_in+2,
			nb_sack_out, packd.sack_tcp + (start_index<<1),
			1);

		if(PRINT_TABLE) load_print_table(packd.id, packd.hook, packd.sfl);
	}
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//update_subflow_control_plane()
//++++++++++++++++++++++++++++++++++++++++++++++++
int update_subflow_control_plane() {
	if( (packd.sfl->tcp_state == ESTABLISHED && packd.fin) ||
	    (packd.sfl->tcp_state > ESTABLISHED && packd.sfl->act_state == CANDIDATE) )
		set_verdict(0,0,0);


	//Loop through tcp states for candidate subflow
	switch(packd.sfl->tcp_state){
	case ESTABLISHED:
		return subflow_established();
	case CLOSE_WAIT:
		return subflow_close_wait();
	case SYN_SENT:
		return subflow_syn_sent();	
	case SYN_REC:
		return subflow_syn_received();
	case FIN_WAIT_1:
		return subflow_fin_wait_1();
	case FIN_WAIT_2:
		return subflow_fin_wait_2();
	case CLOSING:
		return subflow_closing();
	case TIME_WAIT:
		break;
	case LAST_ACK:
		return subflow_last_ack();
	}//end switch sfl->tcp_state
	return 0;	
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//update_packet_input()
//++++++++++++++++++++++++++++++++++++++++++++++++
int update_session_control_plane() {

	int init_sess_state = packd.sess->sess_state;
	int ret = 0;

	switch(packd.sess->sess_state){
	case ESTABLISHED:
		ret = session_established();
		break;
	case SYN_SENT:
		ret = session_syn_sent();	
		break;
	case PRE_SYN_REC_1:
		ret = session_pre_syn_rec_1();
		break;
	case SYN_REC:
		ret = session_syn_rec();
		break;
	case PRE_EST:
		ret = session_pre_est();
		break;
	case FIN_WAIT_1:
		ret = session_fin_wait_1();
		break;
	case FIN_WAIT_2:
		ret = session_fin_wait_2();
		break;
	case PRE_CLOSING:
		ret = session_pre_closing();
		break;
	case PRE_TIME_WAIT:
		ret = session_pre_time_wait();
		break;
	case CLOSING:
		ret = session_closing();
		break;
	case PRE_CLOSE_WAIT:
		ret = session_pre_close_wait();
		break;
	case CLOSE_WAIT:
		ret = session_close_wait();
		break;
	case LAST_ACK:
		ret = session_last_ack();
		break;
	case TIME_WAIT:
		ret = session_time_wait();
	}//end switch
	
	if(packd.sess->sess_state != init_sess_state && !packd.verdict) {

		set_verdict(1,1,0);

	}

	return ret;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//int mangle_packet()
// Initiates all packet processing and mangling
//++++++++++++++++++++++++++++++++++++++++++++++++
int mangle_packet() {

	if(packd.nb_mptcp_options > 0){

		//*****SELF-INDUCED PACKETS******
		if( packd.hook == 3){

			set_verdict(1,0,0);
			return 0;
		}
		//*****CHECK FOR DATA RST******
		if( packd.hook < 3 && packd.fwd_type == M_TO_T && packd.sess != NULL && find_MPsubkind(mptopt, packd.nb_mptcp_options, MPTCP_RST) > -1){

			handle_data_reset_input();
			return(0);
		}
	}

	//*****TCP RESET******
	// 
	//handles RSTs send by tcp
	//sess can be NULL
	if(packd.rst == 1) {

		//handle all other RSTs
		if(packd.hook < 3 && packd.fwd_type == M_TO_T) handle_reset_input();//sent by other MPTCP host
		if(packd.hook > 1 && packd.fwd_type == T_TO_M) handle_reset_output();//sent by TCP
		return 0; //terminate here
	}

	//*****SESSION ESTABLISHMENT******
	//Sess = NULL && SYN only: contemplate session creation or subflow creation
	//   Evaluates MP_CAP or MP_JOIN
	if(packd.sess == NULL) {

		if( packd.syn == 1 && packd.ack == 0) {

			return contemplate_new_session();
		}
		else{
			set_verdict(1,0,0);
			return 0;
		}
	} else {//generic features if session exists

		if(packd.sess->timestamp_flag) update_timestamp();

	}

	//*****DATA-PLANE MANAGEMENT******
	if(packd.sess->sess_state >= ESTABLISHED && packd.sess->sess_state <= TIME_WAIT) {

		if(packd.hook > 1 && packd.fwd_type == T_TO_M) {

			update_conn_level_data();
			determine_thruway_subflow();//sets verdict

			//*****SIDE ACK MANAGEMENT******
			//packet is sent on packd.sfl, which may be last or active
			if(packd.ack == 1) {
			
				//determine side acks and update SANs for them
				find_side_acks();

				//update thruway for ACKs, i.e. no payload
				if(packd.verdict == 0) update_thruway_subflow();//updates verdict
		
				if(packd.verdict == 0) return 0;//packet terminates here

				//prepare DAN and send side ACKS
				if( packd.sess->pA_sflows_data.number > 0) send_side_acks();

			}//end if packd.ACK == 1


			//*****THRUWAY MANAGEMENT: ADD DSN + MP_PRIO******
			if(packd.rst == 0) set_dss_and_prio();

			update_packet_output();

		} else if(packd.hook < 3 && packd.fwd_type == M_TO_T) {//packd.hook == 1

			if(packd.sfl->broken) {
				set_verdict(0,0,0);
				return 0;
			}

			packd.verdict = 0;
			if(packd.sfl->tcp_state >= ESTABLISHED) {
				update_subflow_level_data();
				packd.verdict = 1;//packd.sess->sent_state;
			

				if( packd.nb_mptcp_options > 0 ) {

					process_dss();
					process_remove_addr();
					process_prio();
	
				}//end if packd.nb_mptcp_options

				update_packet_input();
			}

		}//end if hook = 1/3
	}//end if (packd.sess->sess_state >= ESTABLISHED && packd.sess->sess_state <= TIME_WAIT)



	//*****CONTROL-PLANE MANAGEMENT******
	//Subflow control plane: only for INPUT (hook = 1) && CANDIDATE sfls and when session established
	if(packd.hook<3 && packd.fwd_type == M_TO_T && packd.sess->sess_state >= ESTABLISHED)
		update_subflow_control_plane();

	//Session control plane
	return update_session_control_plane();

}

