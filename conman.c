//*****************************************************
//*****************************************************
//
// conman .c 
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

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mptcpproxy_util.h"
#include "tp_heap.h"
#include "sflman.h"
#include "sessman.h"
#include "conman.h"
#include "mptcp_proxy.h"

#include "common.h"

//this is boolean
int con_man_active = 0;
static char fifo_return_header[] = "mptcp_proxy returns: ";

struct con_man_command cmcmd;

//++++++++++++++++++++++++++++++++++++++++++++++++
//uint16_t toss_port_number();
//++++++++++++++++++++++++++++++++++++++++++++++++
uint16_t toss_port_number() {
	return ( (uint16_t) ( (65535.0 - 49152.0) * (  ((double) rand())/ ((double) RAND_MAX) ) )) + 49152;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//init fifos
//++++++++++++++++++++++++++++++++++++++++++++++++
void init_fifos() {

	mkfifo(FIFO_NAME_DOWN, (mode_t) 0666);
	mkfifo(FIFO_NAME_UP, (mode_t) 0666);

	fd_fifo_dwn = open(FIFO_NAME_DOWN, O_RDONLY | O_NONBLOCK);
	fd_fifo_up = open(FIFO_NAME_UP, O_WRONLY | O_NONBLOCK);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//parse_fifo_command
//  fifo_read: input string
//  len: length of fifo_read
//  response: response string returned
//++++++++++++++++++++++++++++++++++++++++++++++++
int parse_fifo_command(char *fifo_read, size_t len, char *response) {
	
	fifo_read[len] = '\0';

	//parse commands
	char fifo_wrds[MAX_FIFO_WRDS][LEN_FIFO_WRD];
	int items_read;
	int count = 0;
	unsigned offset = 0;
	do {
		items_read = sscanf(fifo_read + offset, "%s", fifo_wrds[count]);
		offset += strlen(fifo_wrds[count]) + 1;
		count++;
	} while( items_read > 0 && offset < strlen(fifo_read) && count < MAX_FIFO_WRDS );

	//check if items found
	if(count==0) {
		strcpy(response, fifo_return_header);
		strcat(response,fifo_read);
		strcat(response,"  not recognized - no words tokens - no action");
		return 0;
	}

	//check for first item
	if( (strcmp(fifo_wrds[0],"-L")!=0) &&  (strcmp(fifo_wrds[0],"-A")!=0) && (strcmp(fifo_wrds[0],"-B")!=0) &&
	    (strcmp(fifo_wrds[0],"-D")!=0) &&  (strcmp(fifo_wrds[0],"-S")!=0) && (strcmp(fifo_wrds[0],"-Q")!=0)) {

		strcpy(response, fifo_return_header);
		strcat(response,fifo_wrds[0]);
		strcat(response," not recognized - no action");
		return 0;
	}


	//copy command
	cmcmd.cmd = fifo_wrds[0][1];

	if(cmcmd.cmd=='L') {
		strcpy(response, fifo_return_header);
		attach_session_data(response);
		return 1;
	}


	//find sess
	int i1=1;
	while(i1 < count && strcmp(fifo_wrds[i1],"-sess") != 0 ) i1++;

	if(i1 >= count-1)
		cmcmd.sess = -1;
	else
		cmcmd.sess = atoi(fifo_wrds[i1+1]);

	if( cmcmd.cmd != 'B' || cmcmd.cmd != 'D' || cmcmd.cmd != 'S') {

		//find sfl: Important for 'D' and 'S'
		i1=1;
		while(i1 < count && strcmp(fifo_wrds[i1],"-sfl") != 0 ) i1++;

		if(i1 >= count-1)
			cmcmd.sfl = -1;
		else
			cmcmd.sfl = atoi(fifo_wrds[i1+1]);
	}	


	//find if: Important for 'D' and 'S'
	if( cmcmd.cmd == 'A' || cmcmd.cmd == 'B') {

		i1=1;
		while(i1 < count && strcmp(fifo_wrds[i1],"-if") != 0 ) i1++;

		if(i1 >= count-1)
			strcpy(cmcmd.ifname, "N/A");
		else
			strcpy(cmcmd.ifname, fifo_wrds[i1+1]);

		//find ipl
		i1=1;
		while(i1 < count && strcmp(fifo_wrds[i1],"-ipl") != 0 ) i1++;

		if(i1 >= count-1)
			cmcmd.ip_loc = 0;
		else
			cmcmd.ip_loc = ntohl(inet_addr(fifo_wrds[i1+1]));

		//find ipr
		i1=1;
		while(i1 < count && strcmp(fifo_wrds[i1],"-ipr") != 0 ) i1++;

		if(i1 >= count-1)
			cmcmd.ip_rem = 0;
		else
			cmcmd.ip_rem = ntohl(inet_addr(fifo_wrds[i1+1]));
		
		//find ptl
		i1=1;
		while(i1 < count && strcmp(fifo_wrds[i1],"-ptl") != 0 ) i1++;

		if(i1 >= count-1)
			cmcmd.prt_loc = 0;
		else
			cmcmd.prt_loc = atoi(fifo_wrds[i1+1]);

		//find ptr
		i1=1;
		while(i1 < count && strcmp(fifo_wrds[i1],"-ptr") != 0 ) i1++;

		if(i1 >= count-1)
			cmcmd.prt_rem = 0;//will be filled in later
		else
			cmcmd.prt_rem = atoi(fifo_wrds[i1+1]);
	}


	return 1;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//check_fifo_msg(): reads from fifo and evaluates message
//	returns message to fifo
//++++++++++++++++++++++++++++++++++++++++++++++++
void check_fifo_msg() {

	//receive string
	char buf_in[LEN_FIFO_REQ + 1];
	int ret = read(fd_fifo_dwn, buf_in, LEN_FIFO_REQ);

	if(ret < -1) {
		sprintf(msg_buf, "check_fifo_msg: reading from pipe failed");
		add_msg(msg_buf);
	}

	buf_in[ret] = '\0';
	sprintf(msg_buf, "check_fifo_msg: received \"%s\"", buf_in);
	add_msg(msg_buf);	

	buf_in[ret] = '\0';	
	close(fd_fifo_dwn);
	fd_fifo_dwn = open(FIFO_NAME_DOWN, O_RDONLY | O_NONBLOCK);

	//parse fifo command
	char buf_out[LEN_FIFO_RSP + 1];
	buf_out[0] = '\0';
	int success = parse_fifo_command(buf_in, ret, buf_out);

	//send data up
	fd_fifo_up = open(FIFO_NAME_UP, O_WRONLY | O_NONBLOCK);
	ret = write(fd_fifo_up, buf_out, strlen(buf_out));
	if(ret < -1) {
		sprintf(msg_buf, "check_fifo_msg: writing to pipe failed");
		add_msg(msg_buf);
	}
	close(fd_fifo_up);

	if(success == 0) {
		sprintf(msg_buf, "check_fifo_msg: parse_fifo_command failed");
		add_msg(msg_buf);
		return;
	}
	
	if(cmcmd.cmd != 'L') {
		ret = do_fifo_cmd();
		if(ret == 0) {
			sprintf(msg_buf, "check_fifo_msg: do_fifo_cmd failed");
			add_msg(msg_buf);
		}
	}
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//FIFO: attach session data(buf, sess_id)
//  Lists all subflows, fourtuples for all sessions
//++++++++++++++++++++++++++++++++++++++++++++++++
void attach_session_data(char* resp) {

	char buf[100]; 
	struct subflow *current_sfl, *tmp_sfl;
	HASH_ITER(hh, sfl_hash, current_sfl, tmp_sfl) {
		
		if(strlen(resp) > LEN_FIFO_RSP - 100){
			strcat(resp, "\n...\n");
			return;
		}	

		strcat(resp,"\n");

		strcat(resp,"sfl=");
		sprintf(buf,"%zu",current_sfl->index);
		strcat(resp,buf);

		strcat(resp," sess=");
		sprintf(buf,"%zu",current_sfl->sess->index);
		strcat(resp,buf);

		if(current_sfl->act_state == 1)	strcat(resp," active");	
		else strcat(resp," candid");	

		strcat(resp," if=");
		if(find_interface(&if_tab1, buf, current_sfl->ft.ip_loc)) strcat(resp,buf);
		else strcat(resp,"N/A");

		strcat(resp," ipL=");
		sprintIPaddr(buf, current_sfl->ft.ip_loc);
		strcat(resp,buf);

		strcat(resp," ipR=");
		sprintIPaddr(buf, current_sfl->ft.ip_rem);
		strcat(resp,buf);

		strcat(resp," prtL=");
		sprintf(buf,"%d",current_sfl->ft.prt_loc);
		strcat(resp,buf);

		strcat(resp," prtR=");
		sprintf(buf,"%d",current_sfl->ft.prt_rem);	
		strcat(resp,buf);

		char sess_state_str[20];
		translate_SM_state(current_sfl->sess->sess_state, sess_state_str);
		strcat(resp," sess_state=");
		strcat(resp,sess_state_str);


		char sfl_state_str[20];
		translate_SM_state(current_sfl->tcp_state, sfl_state_str);
		strcat(resp," sfl_state=");
		strcat(resp,sfl_state_str);

	}
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: do_fifo_cmd(): exercises command sent by fifo
//++++++++++++++++++++++++++++++++++++++++++++++++
int do_fifo_cmd() {

	//terminate netfilter program
	if(cmcmd.cmd == 'Q') {
		terminate_loop = 1;
		return 0;
	}

	//find session: find max session index if no session provided
	struct session *curr_sess, *try_sess, *tmp_sess;
	curr_sess = NULL;
	unsigned max_index = 0;
	HASH_ITER(hh, sess_hash, try_sess, tmp_sess) {
		if(try_sess != NULL){	
			if(cmcmd.sess == -1){
				if(try_sess->index >= max_index){
					curr_sess = try_sess;
					max_index = try_sess->index;			
				}
			}
		}
		if((int)try_sess->index == cmcmd.sess) {
			curr_sess = try_sess;
			break;
		}
	}
	
	if(curr_sess==NULL) {
		sprintf(msg_buf,"do_fifo_cmd: sess with id=%d not found - FIFO CMD ABORTED", cmcmd.sess);
		add_msg(msg_buf);	
		return 0;
	}
	
	if(curr_sess->conman_state != '0') {
		sprintf(msg_buf,"do_fifo_cmd: sess->conman_state=%c != 0 - FIFO CMD ABORTED", curr_sess->conman_state);	
		add_msg(msg_buf);
		return 0;
	}
	if(curr_sess->sess_state < ESTABLISHED || curr_sess->sess_state >= TIME_WAIT) {
		curr_sess->conman_state = '0';
		add_msg(msg_buf);
		sprintf(msg_buf,"do_fifo_cmd: sess_state=%d not established - FIFO CMD ABORTED", curr_sess->sess_state);
		return 0;
	} 	

		
	switch(cmcmd.cmd) {
	case 'A':
		return add_sfl_fifo(curr_sess);
		break;
	case 'D':
		return delete_sfl_fifo(curr_sess);
		break;
	case 'S':
		return switch_sfl_fifo(curr_sess);
		break;
	case 'B':
		return break_sfl_fifo(curr_sess);
		break;
	default: 
		return 0;
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: do_add(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
int add_sfl_fifo(struct session *sess) {
	if(cmcmd.cmd != 'A')
		return 0;

	sess->conman_state = 'A';
	struct fourtuple ft;
	if(!determine_fourtuple(sess, &ft)){ 
		sprintf(msg_buf,"add_sfl_fifo: new subflow cannot be created - FIFO CMD ABORTED");
		add_msg(msg_buf);
		return 0;
	}

	if(UPDATE_DEFAULT_ROUTE) update_default_route(ft.ip_loc);

	unsigned char backup = 1;
	if(ALLOW_PEER_MULTIPATH) backup = 0;
	if(initiate_cand_subflow(sess, &ft, backup) == 0){
		sprintf(msg_buf,"add_sfl_fifo: initiate_cand_subflow() creates error - FIFO CMD ABORTED");
		add_msg(msg_buf);
		return 0;
	}
	sprintf(msg_buf,"add_sfl_fifo: new subflow initiated");
	add_msg(msg_buf);
	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: do_delete(struct session *sess, struct subflow *sflx)
//++++++++++++++++++++++++++++++++++++++++++++++++
int delete_sfl_fifo(struct session *sess) {

	//find candidate subflow
	struct subflow *sflx = NULL;

	//find subflow: sfl index provided if cmcmd.sfl >-1; must_be_cand = 1;
	sflx = find_subflow_in_session(sess, (cmcmd.sfl>-1), (size_t) cmcmd.sfl, 1);

	if(sflx == NULL) {

		sprintf(msg_buf, "delete_sfl_fifo: subflow not found - FIFO CMD ABORTED");
		add_msg(msg_buf);
		return 0;

	}

	if( (cmcmd.sfl>-1) && ((int)sflx->index != cmcmd.sfl) ) {

		sprintf(msg_buf, "delete_sfl_fifo: subflow index incorrect - FIFO CMD ABORTED");
		add_msg(msg_buf);
		return 0;

	}

	//check if subflow is candidate
	if(sflx->act_state == 1) {
		sprintf(msg_buf, "delete_sfl_fifo: sfl index=%zu is active, cannot terminate!", sflx->index);
		add_msg(msg_buf);
		return 0;
	}

	
/*

	if(terminate_subflow(sess, sflx) == 0){
		sprintf(msg_buf, "delete_sfl_fifo: terminate_cand_subflow() creates error - FIFO CMD ABORTED");
		add_msg(msg_buf);
		sess->conman_state == '0';
		return 0;
	}
*/
	if(!send_reset_subflow(sflx)) {
		sprintf(msg_buf, "delete_sfl_fifo: resetting subflow() creates error - FIFO CMD ABORTED");
		add_msg(msg_buf);
		//TODO What's intented ?
		//sess->conman_state == '0';
		return 0;
	}


	sprintf(msg_buf, "delete_sfl_fifo: sess id=%zu - subflow deletion initiated", sess->index); 
	add_msg(msg_buf);
	//send entry to event queue for retransmission
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: do_switch(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
int switch_sfl_fifo(struct session *sess) {

	//find candidate subflow
	struct subflow *new_sfl = NULL;

	//find subflow: sfl index provided if cmcmd.sfl >-1; must_be_cand if (cmcmd.sfl == -1);
	new_sfl = find_subflow_in_session(sess, (cmcmd.sfl>-1), (size_t) cmcmd.sfl, (cmcmd.sfl == -1));

	if(new_sfl == NULL) {

		sprintf(msg_buf, "switch_sfl_fifo: subflow not found - FIFO CMD ABORTED");
		add_msg(msg_buf);
		return 0;

	}
	if( (cmcmd.sfl>-1) && ( (int)new_sfl->index != cmcmd.sfl) ) {

		sprintf(msg_buf, "switch_sfl_fifo: subflow index incorrect - FIFO CMD ABORTED");
		add_msg(msg_buf);
		return 0;

	}



	//if(switch_active_sfl(sess, new_sfl)) sess->conman_state = 'S';
	switch_active_sfl(sess, new_sfl);

	if(sess->act_subflow != sess->last_subflow) {
		if(!send_switch_ack(sess->act_subflow, sess->last_subflow)){

			sprintf(msg_buf, "switch_active_sfl: send_switch_ack() returned error");
			add_msg(msg_buf);
		}
	}

	sprintf(msg_buf, "switch_sfl_fifo: sess id=%lu switched from sfl id=%zu to sfl id=%zu",
			sess->index,
			sess->last_subflow->index, sess->act_subflow->index);
	add_msg(msg_buf);

	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//CONMAN: do_break(struct session *sess)
//++++++++++++++++++++++++++++++++++++++++++++++++
int break_sfl_fifo(struct session *sess) {

	//present active subflow will be interrupted
	//if candidate is up, it becomes active subflow
	//if no candidate exists but loc IP address is provided, a new subflow is created
	//if no candidate and no new local IP address but USE_PORT_FOR_NEW_SUBFLOWS, new port on existing loc IP is used
	//otherwise nothing happpens
	//break event is set whenever a new subflow has to be created

	//find candidate subflow
	struct subflow *new_sfl = NULL;
	new_sfl = find_subflow_in_session(sess, (cmcmd.sfl>-1), (size_t) cmcmd.sfl, 1);

	//if new_sfl == NULL try to create new subflow
	if(new_sfl == NULL) {
		sprintf(msg_buf, "break_sfl_fifo: candidate subflow not found -> creating new subflow");
		add_msg(msg_buf);

		//get fourtuple for new subflow (all except active)
		//note: act_subflow != NULL at this point
		cmcmd.ip_loc = 0;
		cmcmd.prt_loc = 0;
		cmcmd.ip_rem = 0;
		cmcmd.prt_rem = 0;
		struct fourtuple ft;
		if(!determine_fourtuple(sess, &ft)) {

			sprintf(msg_buf,"break_sfl_fifo: new subflow cannot be created - FIFO CMD ABORTED");
			add_msg(msg_buf);
			return 0;
		}

		if(UPDATE_DEFAULT_ROUTE) update_default_route(ft.ip_loc);

		//set last subflow to active subflow
		sess->act_subflow->broken = 1;
		sess->cdsn_loc = sess->highest_dan_loc-1;

		unsigned char backup = 0;
		if(initiate_cand_subflow(sess, &ft, backup) == 0){
			sprintf(msg_buf,"break_sfl_fifo: initiating new subflow creates error - FIFO CMD ABORTED");
			add_msg(msg_buf);
			return 0;
		}
	
	} else {
		sprintf(msg_buf,"break_sfl_fifo: sess id=%zu - deleting old sfl id=%zu and using new sfl id=%zu", 
				sess->index, sess->act_subflow->index, new_sfl->index);
		add_msg(msg_buf);

		break_active_sfl(sess, new_sfl);//switches to new subflow in "break" manner

		//send break ack: TPprio for new subflow and REMOVE_ADDR on old address
		send_break_ack(sess->act_subflow, sess->last_subflow->addr_id_loc);

		if(sess->act_subflow->addr_id_loc == sess->last_subflow->addr_id_loc) send_reset_subflow(sess->last_subflow);		

		create_prio_event(&sess->ft, sess->last_subflow->addr_id_loc);//to resend breal ack

		return 1;
	}


	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: check_for_subflow_break(char * const ifname, const uint32_t old_ipaddr)
// this is used when ip address is discontinued
//++++++++++++++++++++++++++++++++++++++++++++++++
void check_for_subflow_break(char * const ifname, const uint32_t old_ipaddr) {

	char buf_ip[34];
	sprintIPaddr(buf_ip, old_ipaddr);
	sprintf(msg_buf,"check_for_subflow_break: if=%s discontinued ip address=%s", ifname, buf_ip);
	add_msg(msg_buf);

	struct session *curr_sess, *tmp_sess;
	int affected = 0;
	HASH_ITER(hh, sess_hash, curr_sess, tmp_sess) {
		
		if(curr_sess != NULL)
			continue;

		int active_broken = 0;
		
		//find broken subflows, set "broken", start teardowntimer for candidates
		struct subflow *sflx;
		for(unsigned j1=0; j1 < curr_sess->pA_sflows.number; j1++){
			sflx = (struct subflow*) curr_sess->pA_sflows.pnts[j1];
			if(  sflx != NULL && strcmp(sflx->ifname_loc, ifname) == 0 && sflx->ft.ip_loc == old_ipaddr) {
					
				affected = 1;
				if(handle_subflow_break(sflx)) {
					active_broken = 1;

					sprintf(msg_buf,"check_for_subflow_break: active broken");
					add_msg(msg_buf);
				} else {
					sprintf(msg_buf,"check_for_subflow_break: candidate broken");
					add_msg(msg_buf);
				}
			}
		}
		
		if(active_broken){

			sprintf(msg_buf,"check_for_subflow_break: active sfl id=%zu broken", curr_sess->act_subflow->index);
			add_msg(msg_buf);

			strcpy(cmcmd.ifname, "");
			cmcmd.ip_loc = 0;
			break_sfl_fifo(curr_sess);
		}
	}

	if(affected) create_remove_addr_event(old_ipaddr);//sends REMOVE_ADDR after some time
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: check_for_remote_break(stuct sesssion * const sess, struct subflow * const sfl_in, unsigned char addr_id_rem)
// this is used when REMOVE_ADDR is received
// sfl_in is the subflow where remove_addr arrived
//++++++++++++++++++++++++++++++++++++++++++++++++
void check_for_remote_break(struct session * const sess, struct subflow * const sfl_in, unsigned char addr_id_rem) {

	sprintf(msg_buf, "check_for_remote_break: addr_id=%u", addr_id_rem);
	add_msg(msg_buf);


	//find broken subflows, set "broken", start teardowntimer for candidates
	int active_broken = 0;		
	struct subflow *sflx;
	for(unsigned j1=0; j1 < sess->pA_sflows.number; j1++){
		sflx = (struct subflow*) sess->pA_sflows.pnts[j1];
		if(sflx != NULL && sflx->addr_id_rem == addr_id_rem) {
			if(handle_subflow_break(sflx)) active_broken = 1;//returns 1 if active
			else send_reset_subflow(sflx);//if candidate
		}
	}
		
	if(!active_broken)
		return;

	struct subflow *new_sfl = NULL;
	if(!sfl_in->broken) new_sfl = sfl_in;
	else new_sfl = find_subflow_in_session(sess, 0, 0, 1);//index not provided, must be candidate

	if(!new_sfl)
		return;

	if(sess->conman_state == 'S') break_during_switch(sess);	
	break_active_sfl(sess, sfl_in);//switches active to sfl_in, sets active to last
	send_reset_subflow(sess->last_subflow);//former active subflow
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: do_make(char * const ifname, const uint32_t new_ipaddr)
// this is used when new ip address or interface comes up
//++++++++++++++++++++++++++++++++++++++++++++++++
void do_make(char * const ifname, const uint32_t new_ipaddr) {
	char buf_ip[34];
	sprintIPaddr(buf_ip, new_ipaddr);
	sprintf(msg_buf, "do_make: if=%s with ip address=%s", ifname, buf_ip);
	add_msg(msg_buf);

	struct session *curr_sess, *tmp_sess;
	HASH_ITER(hh, sess_hash, curr_sess, tmp_sess) {
		if(curr_sess == NULL)
			continue;

		//find broken subflows, set "broken", start teardowntimer for candidates
		struct subflow *sflx;
		for(unsigned j1=0; j1 < curr_sess->pA_sflows.number; j1++) {
			sflx = (struct subflow*) curr_sess->pA_sflows.pnts[j1];
			if(sflx != NULL && strcmp(sflx->ifname_loc, ifname) == 0 &&
					sflx->ft.ip_loc == new_ipaddr) {
				sflx->broken = 0;
				sprintf(msg_buf, "do_make: resetting broken flag for sess_id=%zu, sfl_id=%zu", curr_sess->index, sflx->index);
				add_msg(msg_buf);


			}
		}
		
		//if active subflow is still broken, try break_sfl_fifo()
		if(curr_sess->act_subflow->broken) {
			strcpy(cmcmd.ifname, "");
			cmcmd.ip_loc = 0;
			cmcmd.cmd = 'B';	
			break_sfl_fifo(curr_sess);
		}
	}
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: do_break_before_make(char * const ifname, const uint32_t old_ipaddr, const uint32_t new_ipaddr)
// this is used when ip address changes
// new address may be 0
//++++++++++++++++++++++++++++++++++++++++++++++++
void do_break_before_make(char * const ifname, const uint32_t old_ipaddr, const uint32_t new_ipaddr) {
	char buf_ip_old[34];
	sprintIPaddr(buf_ip_old, old_ipaddr);
	char buf_ip_new[34];
	sprintIPaddr(buf_ip_new, new_ipaddr);

	sprintf(msg_buf, "do_break_before_make: ip address of if=%s changed from %s to %s", ifname, buf_ip_old, buf_ip_new);
	add_msg(msg_buf);

	struct session *curr_sess, *tmp_sess;
	HASH_ITER(hh, sess_hash, curr_sess, tmp_sess) {
		if(curr_sess == NULL)
			continue;

		if(curr_sess->act_subflow == NULL)
			continue;

		if(strcmp(curr_sess->act_subflow->ifname_loc, ifname) == 0 &&
				curr_sess->act_subflow->ft.ip_loc == old_ipaddr) {
			strcpy(cmcmd.ifname, "");
			cmcmd.ip_loc = new_ipaddr;
			cmcmd.cmd = 'B';	
			break_sfl_fifo(curr_sess);
		}
	}
	create_remove_addr_event(old_ipaddr);//does REMOVE_ADDR if address was used by candidates	
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: do_remove_address(const uint32_t old_ipaddr)
//sends REMOVE_ADDR on active subflow in case candidates use the local IP address that has been deleted
//++++++++++++++++++++++++++++++++++++++++++++++++
void do_remove_address(struct session *sess, const uint32_t old_ipaddr) {
	char buf_ip_old[34];
	sprintIPaddr(buf_ip_old, old_ipaddr);

	sprintf(msg_buf, "do_remove_address: remove address %s for sess id=%zu", buf_ip_old, sess->index);
	add_msg(msg_buf);

	int found = 0;
	struct subflow *sflx;
	for(unsigned i=0; i < sess->pA_sflows.number; ++i) {
			
		sflx = (struct subflow*) get_pnt_pA(&sess->pA_sflows, i);
		
		if( sflx->ft.ip_loc == old_ipaddr && sflx->act_state == CANDIDATE && sflx->tcp_state < TIME_WAIT) {
			sprintf(msg_buf, "do_remove_address: THIS DOES NOT WORK. WE SHOULD SEND INDEPENDENT ACK WITH REMOVE_ADDR!");
			add_msg(msg_buf);

			//mapping between address and address_id must be removed in case a connection has more than 256 address changes
			sess->addrid_remove.addr = old_ipaddr;
			sess->addrid_remove.id = sflx->addr_id_loc;
			found = 1;			
		}
	}
	
	
	//in case one of those candidate subflows still existed create a new remove_address_event
	if(found) create_remove_addr_event(old_ipaddr);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//create_remove_addr_event: creates event to remove address
//  ensures retransmission of REMOVE_ADDR
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_remove_addr_event(const uint32_t ipaddr) {

	//create remove_addr event data
	struct remove_addr_event_data *rmadd = malloc(sizeof(struct remove_addr_event_data));
	rmadd->ipaddr = ipaddr;

	//create new tp_event and put packet on retransmit queue
	struct tp_event *evt = malloc( sizeof(struct tp_event) );
	evt->type = REMOVE_ADDR;
	evt->data = (void*) rmadd;

	//insert event
	time_t dsec = REMOVE_ADDR_TIME_INTERVAL; 
	insert_event(evt, dsec, 0);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_remove_addr_event: executes remove_addr message retransmission (REMOVE_ADDR)
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_remove_addr_event(struct tp_event *evt) {
	struct remove_addr_event_data *rmadd = (struct remove_addr_event_data*) evt->data;

	//check if IP address was assigned again
	char ifname[MAX_LENGTH_IFACE_NAME];
	if( !find_interface(&if_tab1, ifname, rmadd->ipaddr) ) {
		struct session *curr_sess, *tmp_sess;
		HASH_ITER(hh, sess_hash, curr_sess, tmp_sess) {
			if(curr_sess != NULL) do_remove_address(curr_sess, rmadd->ipaddr);
		}
	
	}
	delete_remove_addr_event(evt);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_remove_addr__event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_remove_addr_event(struct tp_event *evt) {
	struct remove_addr_event_data *rmadd  = (struct remove_addr_event_data *) evt->data;
	free( rmadd );
	free( evt );
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//determine fourtuple: We assume that act_subflow != NULL
//++++++++++++++++++++++++++++++++++++++++++++++++
int determine_fourtuple(struct session *sess, struct fourtuple *ft) {
	ft->ip_loc = cmcmd.ip_loc;
	ft->ip_rem = cmcmd.ip_rem;
	ft->prt_loc = cmcmd.prt_loc;
	ft->prt_rem = cmcmd.prt_rem;

	//if interface is provided, use that one
	if(ft->ip_loc == 0 && strcmp(cmcmd.ifname, "N/A") !=0)
		ft->ip_loc = find_ipaddr(&if_tab1, cmcmd.ifname);		

	//if not, look for other local ip addresses or eventually, use other local port if permitted 
	if(ft->ip_loc == 0)
		ft->ip_loc = find_other_ipaddr(&if_tab1, sess->act_subflow->ft.ip_loc);

	//if still not, consider giving up
	if(ft->ip_loc == 0){
		if(USE_PORT_FOR_NEW_SUBFLOWS == 0){

			sprintf(msg_buf, "determine_fourtuple: cannot establish fourtuple for new subflow!");
			add_msg(msg_buf);			
			return 0;
		} else {
			ft->ip_loc = sess->act_subflow->ft.ip_loc;
		}
	}

	//if prt_loc not provided, toss one
	if(ft->prt_loc == 0) {
		ft->prt_loc = toss_port_number();
		while(ft->prt_loc == sess->act_subflow->ft.prt_loc ) ft->prt_loc = toss_port_number();
	}

	if(ft->ip_rem == 0)
		ft->ip_rem = sess->act_subflow->ft.ip_rem;

	if(ft->prt_rem == 0)
		ft->prt_rem = sess->act_subflow->ft.prt_rem;

	char buf_ft[100];
	sprintFourtuple(buf_ft, ft);
	sprintf(msg_buf, "determine_fourtuple: 4tuple for new sfl is %s", buf_ft);
	add_msg(msg_buf);

	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//update_default_route: creates new /24 default route based on IP address provided (host format)
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_default_route(uint32_t ip) {
	char ifname[20];
	int found = find_interface(&if_tab1, ifname, ip);
	char s_ip[40];
	sprintIPaddr(s_ip, ip);

	if(!found) {
		sprintf(msg_buf, "update_default_route: inteface not found to ip  = %s", s_ip);
		add_msg(msg_buf);
		return;
	}

	char str[80];
	strcpy(str,"route add default gw ");
	strcat(str, s_ip);

	int i = strlen(str) - 1;
	while(i > 0 && str[i] != '.') i--;

	if(str[i] != '.'){

		sprintf(msg_buf, "update_default_route: do not find '.' in str = %s", str);
		add_msg(msg_buf);
		return;
	}
	str[i+1] = '1';
	str[i+2] = ' ';
	str[i+3] = '\0';
	strcat(str, ifname);

	sprintf(msg_buf, "update_default_route: new route = %s", str);		
	add_msg(msg_buf);

	system("route del default");
	system(str);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//conman01: auxil_toggle: auxilary function. replaces manual toggle commands
//++++++++++++++++++++++++++++++++++++++++++++++++
void auxil_toggle(char c) {

	sprintf(msg_buf, "auxil_toggle: input char=%c", c);
	add_msg(msg_buf);

	switch(c) {
	case 'A':
		//start a new subflow for sesssion id = 0
		cmcmd.cmd = 'A';
		do_fifo_cmd();
		break;

	case 'S':
		cmcmd.sess = 0;
		cmcmd.sfl = -1;
		cmcmd.cmd = 'S';
		do_fifo_cmd();
		break;

	case 'B':
		cmcmd.sess = 0;

		cmcmd.cmd = 'B';
		do_fifo_cmd();
		break;

	case 'Q':
		cmcmd.cmd = 'Q';
		do_fifo_cmd();
		break;
	}
}

