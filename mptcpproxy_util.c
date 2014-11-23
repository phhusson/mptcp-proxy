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


#include "mptcpproxy_util.h"
#include "sha1.h"
#include "hmac.h"

struct print_data prt_data;
struct print_msg_array prt_msg_array;

//++++++++++++++++++++++++++++++++++++++++++++++++
//sn smaller
// returns 1 if a "<" b
//++++++++++++++++++++++++++++++++++++++++++++++++
int sn_smaller(uint32_t a, uint32_t b) { return ((a-b) > (b-a));}

//++++++++++++++++++++++++++++++++++++++++++++++++
//sn smaller_equal
// returns 1 if a "<=" b
//++++++++++++++++++++++++++++++++++++++++++++++++
int sn_smaller_equal(uint32_t a, uint32_t b){ return ((a-b) >= (b-a));}


//++++++++++++++++++++++++++++++++++++++++++++++++
//translate_SM_state
//++++++++++++++++++++++++++++++++++++++++++++++++
void translate_SM_state(int state_nb, char *state_str){
	switch(state_nb){

 	case CLOSED: strcpy(state_str,"CLOSED"); break;
	case SYN_SENT: strcpy(state_str,"SYN_SENT"); break;
	case PRE_SYN_REC_1: strcpy(state_str,"PRE_SYN_REC_1"); break;
	case PRE_SYN_REC_2: strcpy(state_str,"PRE_SYN_REC_2"); break;
	case SYN_REC: strcpy(state_str,"SYN_REC"); break;
	case PRE_EST: strcpy(state_str,"PRE_EST"); break;
	case ESTABLISHED: strcpy(state_str,"ESTABLISHED"); break;
	case FIN_WAIT_1: strcpy(state_str,"FIN_WAIT_1"); break;
	case FIN_WAIT_2: strcpy(state_str,"FIN_WAIT_2"); break;
	case PRE_CLOSING: strcpy(state_str,"PRE_CLOSING"); break;
	case PRE_TIME_WAIT: strcpy(state_str,"PRE_TIME_WAIT"); break;
	case CLOSING: strcpy(state_str,"CLOSING"); break;
	case PRE_CLOSE_WAIT: strcpy(state_str,"PRE_CLOSE_WAIT"); break;
	case CLOSE_WAIT: strcpy(state_str,"CLOSE_WAIT"); break;
	case LAST_ACK: strcpy(state_str,"LAST_ACK"); break;
	case TIME_WAIT: strcpy(state_str,"TIME_WAIT"); break;
	default: strcpy(state_str,"UNRECK");
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//translate_event_state
//++++++++++++++++++++++++++++++++++++++++++++++++
void translate_event_state(int event_nb, char *state_str){
	switch(event_nb){
 	case RETRANSMIT: strcpy(state_str,"RETRANSMIT"); break;
	case SESS_BREAK: strcpy(state_str,"SESS_BREAK"); break;
	case SFL_BREAK: strcpy(state_str,"SFL_BREAK"); break;
	case PRIO: strcpy(state_str,"PRIO"); break;
	case SESS_CLOSE: strcpy(state_str,"SESS_CLOSE"); break;
	case SFL_CLOSE: strcpy(state_str,"SFL_CLOSE"); break;
	case REMOVE_ADDR: strcpy(state_str,"REMOVE_ADDR"); break;
	default: strcpy(state_str,"UNRECK");
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_error
// Prints out a string and exits
//++++++++++++++++++++++++++++++++++++++++++++++++
inline void handle_error(char *message, int exit_flag) {
	printf("%s\n", message);
	if(exit_flag){
		printf("exit set\n");
		 exit(1);	
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//print_msg
// Prints message
//++++++++++++++++++++++++++++++++++++++++++++++++
inline void print_msg(char *msg) {
	printf("%s\n", msg);
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//print_buffer
// Prints out a string and exits
//++++++++++++++++++++++++++++++++++++++++++++++++
inline void print_buffer(unsigned char *buf, uint16_t len, int hex_flag) {
	int i;
	for(i=0;i<len;i++) {
		if(hex_flag) {
			printf("%x.", buf[i]);
			if(i%4 == 3) printf(" ");
		} else {
			printf("%u.", buf[i]);
			if(i%4 == 3) printf(" ");
		}
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//sprint_buffer
// Prints buffer to string
//++++++++++++++++++++++++++++++++++++++++++++++++
extern inline void sprint_buffer(unsigned char *buf_in, char *str_out, uint16_t len, int hex_flag) {
	int i;
	
	str_out[0] = '\0';
	char buf[5];
	for(i=0;i<len;i++) {
		if(hex_flag){
			sprintf(buf, "%x.", buf_in[i]);
			strcat(str_out, buf);
			if(i%4 == 3) strcat(str_out," ");
		} else {
			sprintf(buf, "%u.", buf_in[i]);
			strcat(str_out, buf);
			if(i%4 == 3) strcat(str_out," ");
		}
	}
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//void init_msg_data();
// Initializes msg printing
//++++++++++++++++++++++++++++++++++++++++++++++++
void init_msg_data() {

	gettimeofday(&prt_msg_array.start, NULL);
	prt_msg_array.prt_msgs = malloc(MAX_MSG_LINES * sizeof(struct print_msg*));//creates an array of pointers to msgs
	prt_msg_array.nmb_msg = 0;
	prt_msg_array.curr_msg_index = 0;

	int i;
	for(i=0;i<MAX_MSG_LINES; i++) {
		prt_msg_array.prt_msgs[i] = malloc(sizeof(struct print_msg));
	}
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//void add_msg(char* msg);
//Adds msg to msg array
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_msg(char *msg){
	prt_msg_array.prt_msgs[prt_msg_array.curr_msg_index]->index = prt_msg_array.nmb_msg;
	gettimeofday(&prt_msg_array.prt_msgs[prt_msg_array.curr_msg_index]->now, NULL);
	 

	if(strlen(msg) < MAX_MSG_LENGTH) {
		strncpy(prt_msg_array.prt_msgs[prt_msg_array.curr_msg_index]->msg, msg, strlen(msg)+1);
	} else {
		strncpy(prt_msg_array.prt_msgs[prt_msg_array.curr_msg_index]->msg, msg, MAX_MSG_LENGTH);
		prt_msg_array.prt_msgs[prt_msg_array.curr_msg_index]->msg[MAX_MSG_LENGTH] = '\0';
	}

	//inc msg counter
	prt_msg_array.nmb_msg++;//with natural overflow
	prt_msg_array.curr_msg_index++;
	prt_msg_array.curr_msg_index %= MAX_MSG_LINES;//loops around
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//void terminate_msg_data();
// Prints prt_msg_array and closes file
//++++++++++++++++++++++++++++++++++++++++++++++++
void terminate_msg_data(){

	prt_msg_array.file_msg = fopen(FILE_NAME_MSG, "w");
	fprintf(prt_msg_array.file_msg, "index\ttime[s]\tmsg\n");

	int i;
	struct print_msg *prt;
	if(prt_msg_array.curr_msg_index < prt_msg_array.nmb_msg) {//it has looped around yet
		for(i=prt_msg_array.curr_msg_index; i<MAX_MSG_LINES;i++) {
			prt = prt_msg_array.prt_msgs[i];
			double dtime = 1.0 * (prt->now.tv_sec - prt_msg_array.start.tv_sec) +  (prt->now.tv_usec - prt_msg_array.start.tv_usec)/1000000.0;
	
			fprintf(prt_msg_array.file_msg,"%u\t%f\t%s\n", prt->index, dtime, prt->msg);
		}
	}

	for(unsigned i=0; i<prt_msg_array.curr_msg_index;i++) {
		prt = prt_msg_array.prt_msgs[i];
		double dtime = 1.0 * (prt->now.tv_sec - prt_msg_array.start.tv_sec) +  (prt->now.tv_usec - prt_msg_array.start.tv_usec)/1000000.0;
	
		fprintf(prt_msg_array.file_msg,"%u\t%f\t%s\n", prt->index, dtime, prt->msg);
	}
	fclose(prt_msg_array.file_msg);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//void init_print_data();
// Initializes data printing
//++++++++++++++++++++++++++++++++++++++++++++++++
void init_print_data() {

	gettimeofday(&prt_data.start, NULL);
	prt_data.print_line_array = malloc(MAX_PRINT_LINES * sizeof(struct print_line*));//creates an array of pointers to printlines
	if(PRINT_TABLE) prt_data.print_table_array = malloc(MAX_PRINT_LINES * sizeof(struct print_table*));
	prt_data.nmb_lines = 0;
	prt_data.nmb_tables = 0;
	prt_data.do_print = 0;

	int i;
	for(i=0;i<MAX_PRINT_LINES; i++) {
		prt_data.print_line_array[i] = malloc(sizeof(struct print_line));
		if(PRINT_TABLE) prt_data.print_table_array[i] = malloc(sizeof(struct print_table));

	}
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//void load_print_line();
// loads data to packd.print_line
//++++++++++++++++++++++++++++++++++++++++++++++++
void load_print_line(uint32_t id, size_t hook, 
			size_t sess_id, size_t sfl_id, 
			int rex, uint32_t len, unsigned char flags, 
			uint32_t ssn, uint32_t san, uint32_t dsn, uint32_t dan, 
			unsigned char nb_sack_in, uint32_t *sack_in, unsigned char nb_sack_out, uint32_t *sack_out, int verdict) {

	if(prt_data.nmb_lines >= MAX_PRINT_LINES) return;

	packd.prt_line.id = id;
	packd.prt_line.hook = hook;
	packd.prt_line.sess_id = sess_id;
	packd.prt_line.sfl_id = sfl_id;
	packd.prt_line.rex = rex;
	packd.prt_line.paylen = len;
	packd.prt_line.flags = flags;

	packd.prt_line.ssn = ssn;
	packd.prt_line.san = san;
	packd.prt_line.dsn = dsn;
	packd.prt_line.dan = dan;

	packd.prt_line.verdict = verdict;


	unsigned char i;
	unsigned char nb;
	nb = (nb_sack_in < 3)? nb_sack_in:3;
	for(i=0;i<(nb<<1);i++) packd.prt_line.sack_in[i] = sack_in[i];
	for(i=(nb<<1);i<6;i++) packd.prt_line.sack_in[i] = 0;
	packd.prt_line.nb_sack_in = nb_sack_in;

	nb = (nb_sack_out < 3)? nb_sack_out:3;
	for(i=0;i<(nb<<1);i++) packd.prt_line.sack_out[i] = sack_out[i];
	for(i=(nb<<1);i<6;i++) packd.prt_line.sack_out[i] = 0;
	packd.prt_line.nb_sack_out = nb_sack_out;

	add_print_data();
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//void load_print_table();
//++++++++++++++++++++++++++++++++++++++++++++++++
void load_print_table(uint32_t id, size_t hook, struct subflow *sfl) {

	if(prt_data.nmb_tables >= MAX_PRINT_LINES) return;
	if(sfl == NULL) return;

	uint32_t i = prt_data.nmb_tables;

	prt_data.print_table_array[i]->id = id;
	prt_data.print_table_array[i]->hook = hook;
	prt_data.print_table_array[i]->sfl_id = sfl->index;

	struct map_table *map;
	if(hook == 1) map = sfl->map_recv;
	else map = sfl->map_send;

	struct map_entry *e = map->top;
	unsigned char j = 0;

	uint32_t dsn_offset;
	uint32_t ssn_offset;
	if(hook == 1) {
		dsn_offset = sfl->sess->idsn_rem;
		ssn_offset = sfl->isn_rem;
	}
	else{
		dsn_offset = sfl->sess->idsn_loc;
		ssn_offset = sfl->isn_loc;
	}

	while(e && j < 10) {
		prt_data.print_table_array[i]->dsn[j] = e->dsn - dsn_offset;
		prt_data.print_table_array[i]->ssn[j] = e->ssn - ssn_offset;
		prt_data.print_table_array[i]->range[j] = e->range;
		e = e->next;
		j++;
	}
	prt_data.print_table_array[i]->nb_entries = j;

	prt_data.nmb_tables++;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//void add_print_data();
// adds a print_line to print_data
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_print_data() {

	if(!prt_data.do_print || prt_data.nmb_lines >= MAX_PRINT_LINES) return;

	gettimeofday(&packd.prt_line.now, NULL);
	memcpy(prt_data.print_line_array[prt_data.nmb_lines], &packd.prt_line, sizeof(struct print_line));

	prt_data.nmb_lines++;
	if(prt_data.nmb_lines == MAX_PRINT_LINES) terminate_print_data();
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//void terminate_print_data();
// Prints print_line_array and closes file
//++++++++++++++++++++++++++++++++++++++++++++++++
void terminate_print_data() {

	sprintf(msg_buf, "terminate_print_data: number of lines=%u", prt_data.nmb_lines);
	add_msg(msg_buf);
	prt_data.file1 = fopen(FILE_NAME_1, "w");
	prt_data.file3 = fopen(FILE_NAME_3, "w");
	sprintf(msg_buf, "terminate_print_data: file1 pnt=%lu", (long unsigned int) prt_data.file1);
	add_msg(msg_buf);

	fprintf(prt_data.file1,"id \thook \ttime \tsess \tsfl");
	fprintf(prt_data.file1,"\trex \tsyn \tack \tfin \trst \tlen");
	fprintf(prt_data.file1,"\tssn \tsan \tdsn \tdan");
	fprintf(prt_data.file1,"\tnb_sack_ssn \tLsack_ssn_1 \tRsack_ssn_1 \tLsack_ssn_2 \tRsack_ssn_2 \tLsack_ssn_3 \tRsack_ssn_3");
	fprintf(prt_data.file1,"\tnb_sack_dsn \tLsack_dsn_1 \tRsack_dsn_1 \tLsack_dsn_2 \tRsack_dsn_2 \tLsack_dsn_3 \tRsack_dsn_3");
	fprintf(prt_data.file1,"\tverdict\n");

	fprintf(prt_data.file3,"id \thook \ttime \tsess \tsfl");
	fprintf(prt_data.file3,"\trex \tsyn \tack \tfin \trst \tlen");
	fprintf(prt_data.file3,"\tssn \tsan \tdsn \tdan");
	fprintf(prt_data.file3,"\tnb_sack_dsn \tLsack_dsn_1 \tRsack_dsn_1 \tLsack_dsn_2 \tRsack_dsn_2 \tLsack_dsn_3 \tRsack_dsn_3");
	fprintf(prt_data.file3,"\tnb_sack_ssn \tLsack_ssn_1 \tRsack_ssn_1 \tLsack_ssn_2 \tRsack_ssn_2 \tLsack_ssn_3 \tRsack_ssn_3");
	fprintf(prt_data.file3,"\tverdict\n");

	for(unsigned i=0;i<prt_data.nmb_lines;i++) {

		struct print_line *prt = prt_data.print_line_array[i];
		double dtime = 1.0 * (prt->now.tv_sec - prt_data.start.tv_sec) +  (prt->now.tv_usec - prt_data.start.tv_usec)/1000000.0;
	
		if(prt->hook == 1){
			fprintf(prt_data.file1,"%lu\t%zu\t%f\t%zu\t%zu", (long unsigned int) prt->id, prt->hook, dtime, prt->sess_id, prt->sfl_id);

			fprintf(prt_data.file1,"\t%d\t%d\t%d\t%d\t%d\t%u",
				prt->rex, (prt->flags)>>1 & 0x01,(prt->flags)>>4 & 0x01,(prt->flags) & 0x01,(prt->flags)>>2 & 0x01, prt->paylen);
			fprintf(prt_data.file1,"\t%lu\t%lu",(long unsigned int) prt->ssn, (long unsigned int) prt->san);
			fprintf(prt_data.file1,"\t%lu\t%lu",(long unsigned int) prt->dsn, (long unsigned int) prt->dan);

			fprintf(prt_data.file1,"\t%u \t%lu \t%lu \t%lu \t%lu \t%lu \t%lu", prt->nb_sack_in, 
				(long unsigned) prt->sack_in[0], (long unsigned) prt->sack_in[1],
				(long unsigned) prt->sack_in[2], (long unsigned) prt->sack_in[3],
				(long unsigned) prt->sack_in[4], (long unsigned) prt->sack_in[5]);
			fprintf(prt_data.file1,"\t%u \t%lu \t%lu \t%lu \t%lu \t%lu \t%lu", prt->nb_sack_out,
 				(long unsigned) prt->sack_out[0], (long unsigned) prt->sack_out[1],
				(long unsigned) prt->sack_out[2], (long unsigned) prt->sack_out[3],
				(long unsigned) prt->sack_out[4], (long unsigned) prt->sack_out[5]);

			fprintf(prt_data.file1,"\t%d\n",prt->verdict);	

		}
		else{
			fprintf(prt_data.file3,"%lu\t%zu\t%f\t%zu\t%zu", (long unsigned int) prt->id, prt->hook, dtime, prt->sess_id, prt->sfl_id);

			fprintf(prt_data.file3,"\t%d\t%d\t%d\t%d\t%d\t%u",
				prt->rex, (prt->flags)>>1 & 0x01,(prt->flags)>>4 & 0x01,(prt->flags) & 0x01,(prt->flags)>>2 & 0x01, prt->paylen);
			fprintf(prt_data.file3,"\t%lu\t%lu",(long unsigned int) prt->ssn, (long unsigned int) prt->san);

			fprintf(prt_data.file3,"\t%lu\t%lu",(long unsigned int) prt->dsn, (long unsigned int) prt->dan);

			fprintf(prt_data.file3,"\t%u \t%lu \t%lu \t%lu \t%lu \t%lu \t%lu", prt->nb_sack_in, 
				(long unsigned) prt->sack_in[0], (long unsigned) prt->sack_in[1],
				(long unsigned) prt->sack_in[2], (long unsigned) prt->sack_in[3],
				(long unsigned) prt->sack_in[4], (long unsigned) prt->sack_in[5]);
			fprintf(prt_data.file3,"\t%u \t%lu \t%lu \t%lu \t%lu \t%lu \t%lu", prt->nb_sack_out,
 				(long unsigned) prt->sack_out[0], (long unsigned) prt->sack_out[1],
				(long unsigned) prt->sack_out[2], (long unsigned) prt->sack_out[3],
				(long unsigned) prt->sack_out[4], (long unsigned) prt->sack_out[5]);

			fprintf(prt_data.file3,"\t%d\n",prt->verdict);	
		}



	}


	if(PRINT_TABLE) {

		sprintf(msg_buf, "terminate_print_data: number of tables =%u", prt_data.nmb_tables);
		add_msg(msg_buf);		
		prt_data.file10 = fopen(FILE_NAME_10, "w");
		prt_data.file30 = fopen(FILE_NAME_30, "w");
	
		fprintf(prt_data.file10,"id \thook \tsfl \n");
		fprintf(prt_data.file30,"id \thook \tsfl \n");

		for(unsigned i=0; i<prt_data.nmb_tables; i++) {

			struct print_table *prtt = prt_data.print_table_array[i];

			if(prtt->hook == 1) {
				fprintf(prt_data.file10,"%lu\t%zu\t%zu\t", (long unsigned int) prtt->id, prtt->hook, prtt->sfl_id);

				for(int j=0; j<prtt->nb_entries; j++) {
					fprintf(prt_data.file10,"[%lu,%lu][%lu,%lu]\t", 
					(long unsigned) prtt->dsn[j], (long unsigned) (prtt->dsn[j] + prtt->range[j] - 1),
					(long unsigned) prtt->ssn[j], (long unsigned) (prtt->ssn[j] + prtt->range[j] - 1));
				}					
				fprintf(prt_data.file10,"\n");
			} else{
				fprintf(prt_data.file30,"%lu\t%zu\t%zu\t", (long unsigned int) prtt->id, prtt->hook, prtt->sfl_id);

				for(int j=0; j<prtt->nb_entries; j++){
					fprintf(prt_data.file30,"[%lu,%lu][%lu,%lu]\t", 
					(long unsigned) prtt->dsn[j], (long unsigned) (prtt->dsn[j] + prtt->range[j] - 1),
					(long unsigned) prtt->ssn[j], (long unsigned) (prtt->ssn[j] + prtt->range[j] - 1));
				}					
				fprintf(prt_data.file30,"\n");
			}
		}
	}



	fclose(prt_data.file1);
	fclose(prt_data.file3);
	fclose(prt_data.file10);
	fclose(prt_data.file30);
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//void print_sack(uint32_t *sack, unsigned char nb_sack);
// Prints sack array
//++++++++++++++++++++++++++++++++++++++++++++++++
void print_sack(uint32_t *sack, unsigned char nb_sack) {
	int i;
	printf("print_sack:\n");
	for(i=0;i<nb_sack;i++)	printf("[%lu, %lu] ", (long unsigned) sack[(i<<1)], (long unsigned) sack[(i<<1)+1]);
	printf("\n");
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//util: get_rand: 
//++++++++++++++++++++++++++++++++++++++++++++++++
uint32_t get_rand() {
	uint32_t nmb;
	nmb = rand();
	nmb += ( (rand()%2) <<31);
	return nmb;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create_key: 
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_key(uint32_t *key) {
	*key = get_rand();
	*(key + 1) = get_rand();
	return;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create IDSN: 32bit trunc of SHA1(key)
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_idsn_token(uint32_t * const key, uint32_t *idsn, uint32_t *token) {
	uint32_t resblock[5];
	sha1_buffer ( (const char *) key, 8, (unsigned char *) resblock);
	*token = (resblock[0]);
	*idsn = ntohl( *( resblock+4) );
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create_mac: 20B mac of key = keyA || keyB and msg = R_A || R_B
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_mac(uint32_t *keyA, uint32_t *keyB, uint32_t rand_nmb_A, uint32_t rand_nmb_B, uint32_t* mac){  
	uint32_t key[4];
	memcpy(key, keyA, 8);
	memcpy(key+2, keyB, 8);

	uint32_t msg[2];
	msg[0] = rand_nmb_A;
	msg[1] = rand_nmb_B;
	hmac_sha1(key, 16, msg, 8, (void*) mac); 
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create Token
//++++++++++++++++++++++++++++++++++++++++++++++++
inline uint32_t create_token(uint32_t idsn) {
	//Token is derived from IDSN
	return idsn;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create ISSN
//++++++++++++++++++++++++++++++++++++++++++++++++
uint32_t create_issn() {
	//since rand() only creates a positive long int, 
	// it covers only 31 bits.
	// therefore we add a random bit at the 32 position
	uint32_t ISSN = rand();

	ISSN += ( (rand()%2) <<31);

	return ISSN;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//util: convert IP address from uint32_t to char
//  IP address must be in host format
//++++++++++++++++++++++++++++++++++++++++++++++++
inline void printIPaddr(uint32_t ipaddr) {
	printf("%d.%d.%d.%d",(ipaddr>>24)&0xff,(ipaddr>>16)&0xff,(ipaddr>>8)&0xff,ipaddr&0xff);	
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//util: convert IP address from uint32_t to char
//  IP address must be in host format
//++++++++++++++++++++++++++++++++++++++++++++++++
inline void sprintIPaddr(char* buf, uint32_t ipaddr) {
	sprintf(buf, "%d.%d.%d.%d",(ipaddr>>24)&0xff,(ipaddr>>16)&0xff,(ipaddr>>8)&0xff,ipaddr&0xff);
	return;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: printFourtuple
//++++++++++++++++++++++++++++++++++++++++++++++++
inline void printFourtuple(struct fourtuple *ft) {
	printf("ipL=");
	printIPaddr(ft->ip_loc);
	printf(" ipR=");
	printIPaddr(ft->ip_rem);
	printf(" prtL=%u prtR=%u\n", ft->prt_loc, ft->prt_rem);
	return;

}

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: sprintFourtuple
//++++++++++++++++++++++++++++++++++++++++++++++++
void sprintFourtuple(char* buf, struct fourtuple *ft) {
	char buf_loc[34];
	char buf_rem[34];

	sprintIPaddr(buf_loc, ft->ip_loc);
	sprintIPaddr(buf_rem, ft->ip_rem);

	sprintf(buf, "ipL=%s ipR=%s prtL=%u prtR=%u", buf_loc, buf_rem, ft->prt_loc, ft->prt_rem);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//util: mirrorFourtuple: switches loc and rem
//++++++++++++++++++++++++++++++++++++++++++++++++
void mirrorFourtuple(struct fourtuple *ft) {
	uint32_t ip_buf = ft->ip_loc;
	uint16_t prt_buf = ft->prt_loc;
	ft->ip_loc = ft->ip_rem;
	ft->prt_loc = ft->prt_rem;
	ft->ip_rem = ip_buf;
	ft->prt_rem = prt_buf;
}


//HERE COMES POINTER ARRAY

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: init_pA: Initializes pntArray
//++++++++++++++++++++++++++++++++++++++++++++++++
void init_pA(struct pntArray *pa) {
	pa->alloc = 10;
	pa->pnts = malloc(pa->alloc * sizeof(void*));
	pa->number = 0;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//util: add_pnt_pA: Adds pointer to pntArray
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_pnt_pA(struct  pntArray *pa, void *pnt) {
	if(pa->number+1 >= pa->alloc){
		pa->alloc+=10;
		pa->pnts = realloc(pa->pnts, pa->alloc * sizeof(void*));
	}

	*(pa->pnts + pa->number) = pnt;
	pa->number++;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//util: write_index_pA: Writes to pnt to index in pntArray
//++++++++++++++++++++++++++++++++++++++++++++++++
void write_pnt_pA(struct pntArray *pa, int index, void *pnt) {
	if(index >= (int)pa->number || index < 0) return;
	*(pa->pnts + index) = pnt;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: del_index_pA: Deletes pnt to index in pntArray and puts NULL in the spot
//++++++++++++++++++++++++++++++++++++++++++++++++
void del_index_pA(struct pntArray *pa, int index) {
	if(index >= (int)pa->number || index < 0) return;

	for(unsigned i = index; i< pa->number-1; i++){
		*(pa->pnts+i) = *(pa->pnts +i+1);
	}
	pa->number--;

}

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: get_index_pA: Gets index to pnt in pntArray 
// -1 if not found
//++++++++++++++++++++++++++++++++++++++++++++++++
int get_index_pA(struct  pntArray *pa, void *pnt) {
	unsigned i=0;
	while(i < pa->number && ( *(pa->pnts+i) != pnt) ) i++;

	if( *(pa->pnts+i) != pnt) return -1;
	return i;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//util: get_pnt_pA: Gets pnt to index in anyArray 
// NULL if not found
//++++++++++++++++++++++++++++++++++++++++++++++++
void* get_pnt_pA(struct  pntArray *pa, int index) {
	if(index >= (int)pa->number || index < 0) return NULL;

	return *(pa->pnts+index);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: del_pnt_pA: Deletes pnt from pntArray (if present)
//++++++++++++++++++++++++++++++++++++++++++++++++
void del_pnt_pA(struct pntArray *pa, void *pnt) {
	int index = get_index_pA(pa, pnt);
	del_index_pA(pa, index);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: clear_pA(index_pntArray* pa)
//++++++++++++++++++++++++++++++++++++++++++++++++
void clear_pA(struct  pntArray *pa) {
	pa->number = 0;
	free(pa->pnts);

}
