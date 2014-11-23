 //*****************************************************
//*****************************************************
//
// mptcp_proxy.c 
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

#include "tp_heap.h"
#include "mptcpproxy_util.h"
#include "packman.h"
#include "sflman.h"
#include "sessman.h"
#include "conman.h"
#include "mptcp_proxy.h"
#include "mangleman.h"
#include "conman.h"
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


//netfilter_queue variables
struct nfq_handle *h;
struct nfq_q_handle *qh;
struct nfnl_handle *nh;
int nf_fd;
char nf_buf[4096] __attribute__ ((aligned));

//socket descriptor for raw socket and buffer fo raw socket
int raw_sd;
unsigned char raw_buf[400] __attribute__ ((aligned));// = malloc( 60 * sizeof(unsigned char));

//buffer for new packet if needed
unsigned char new_data[4096] __attribute__ ((aligned));

struct packet_data packd;


//ip tables
char iptables_string[200];

struct if_table if_tab1;
struct if_table if_tab2;
//struct if_alias *alias_hash = NULL;


PriorityQueue PQ;

struct print_data prt_data;


//++++++++++++++++++++++++++++++++++++++++++++++++
//clear hash tables
//++++++++++++++++++++++++++++++++++++++++++++++++
void clear_hash_tables() {
//	alias_hash = NULL;
	sfl_hash = NULL;
	sfl_index_hash = NULL;
	sfl_pnt_hash = NULL;
	sess_hash = NULL;		
	sess_parms_hash = NULL;
	HASH_CLEAR(hh,sfl_hash);
	HASH_CLEAR(hh,sfl_index_hash);
	HASH_CLEAR(hh,sfl_pnt_hash);
	HASH_CLEAR(hh,sess_hash);
	HASH_CLEAR(hh,sess_parms_hash);

}

//++++++++++++++++++++++++++++++++++++++++++++++++
//subflow_IPtables: adds or deletes a subflow from IP tables
// 	add if add == 1 otherwise delete
//	ports and ip addresses in network notation
//++++++++++++++++++++++++++++++++++++++++++++++++
void subflow_IPtables(
	char op, 
	int hook, 
	uint32_t ip_loc, 
	uint16_t prt_loc, 
	uint32_t ip_rem, 
	uint16_t prt_rem) {

	char str_ip_loc[20];
	char str_ip_rem[20];

	sprintIPaddr(str_ip_loc, ip_loc);
	sprintIPaddr(str_ip_rem, ip_rem);

	if(op != 'A' && op !='D') {
		return;
	}

	iptables_string[0] = '\0';	
	switch(hook){

	case 1:	
		sprintf(iptables_string, 
		"iptables -%c INPUT -p tcp -s %s -d %s --sport %u --dport %u -j QUEUE", 
		op, str_ip_rem, str_ip_loc, 
		(unsigned int) prt_rem, (unsigned int) prt_loc );
		add_msg(iptables_string);
		system(iptables_string);
		break;
	case 2:
		sprintf(iptables_string, 
		"iptables -%c FORWARD -p tcp -s %s -d %s --sport %u --dport %u -j QUEUE", 
		op, str_ip_rem, str_ip_loc, 
		(unsigned int) prt_rem, (unsigned int) prt_loc );
		add_msg(iptables_string);
		system(iptables_string);
		break;
	case 3:	
		sprintf(iptables_string, 
		"iptables -%c OUTPUT -p tcp -s %s -d %s --sport %u --dport %u -j QUEUE", 
		op, str_ip_loc, str_ip_rem, 
		(unsigned int) prt_loc, (unsigned int) prt_rem );
		add_msg(iptables_string);
		system(iptables_string);
		break;
	}	
	
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//void handle_interface_changes()
// Checks interface and ip address changes when trigger 
//  is received by select in run_loop()
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_interface_changes() {

	 char *ifname = malloc(11 * sizeof(char));
	strcpy(ifname,"\0");

	uint32_t new_ip = 0;
	uint32_t old_ip = 0;
	char buf_ip_new[16];
	char buf_ip_old[16];
	
	update_interfaces(&if_tab2, &ifname, &old_ip, &new_ip);
	old_ip = 0;
	new_ip = 0;


	load_host_info(&if_tab2, 0, 1);//load host info into table 2, include aliases

	//look if there's new interface
	//check for new interface
	for(unsigned i=0;i<if_tab2.nb_if;i++) {//is there some IF in tab2 that's missing in tab1
		int found = 0;
		for(unsigned j=0;j<if_tab1.nb_if;j++) {
			if( strcmp(if_tab1.ifname[j], if_tab2.ifname[i]) == 0) found = 1;
		}

		if(!found && strstr(if_tab2.ifname[i],":") == 0) {//new interface found
			new_ip = find_ipaddr(&if_tab2, if_tab2.ifname[i]);
			if(new_ip != 0){

				sprintIPaddr(buf_ip_new, new_ip);
				sprintf(msg_buf, "handle_interface_changes: new interface=%s found with ipaddr=%s", if_tab2.ifname[i], buf_ip_new);
				add_msg(msg_buf);

				update_iftable(&if_tab1, if_tab2.ifname[i], new_ip, &old_ip, 0, 0);
				check_for_session_break(&if_tab1, i, old_ip);//checks if sess.ft->iploc = old ip and assigns as alias ip
				fix_alias_arrays(&if_tab1, (if_tab1.nb_if)-1);		

				
			}
		}
	}

	//check for old interface with new IP address
	for(unsigned i=0;i<if_tab2.nb_if;i++) {//is there some IF in tab2 that's missing in tab1

		for(unsigned j=0;j<if_tab1.nb_if;j++) {
			if( strcmp(if_tab1.ifname[j], if_tab2.ifname[i]) == 0) {
				old_ip = find_ipaddr(&if_tab1, if_tab1.ifname[j]);
				new_ip = find_ipaddr(&if_tab2, if_tab2.ifname[i]);
				if(old_ip == 0) {

					sprintIPaddr(buf_ip_new, new_ip);
					sprintIPaddr(buf_ip_old, old_ip);
					sprintf(msg_buf, "handle_interface_changes: interface=%s is up again with IP %s", if_tab2.ifname[i], buf_ip_new);
					add_msg(msg_buf);

					if(new_ip != 0) {
						update_iftable(&if_tab1, if_tab2.ifname[i], new_ip, &old_ip, 0, 0);
						reinstate_old_alias(&if_tab1, j, &if_tab2);
						fix_alias_arrays(&if_tab1, j);
						do_make(if_tab2.ifname[i], new_ip);
					}

				} else {

					if(new_ip != old_ip){

						sprintIPaddr(buf_ip_new, new_ip);
						sprintIPaddr(buf_ip_old, old_ip);
						sprintf(msg_buf, "handle_interface_changes: interface=%s changed IP from %s to %s", if_tab2.ifname[i], buf_ip_old, buf_ip_new);
						add_msg(msg_buf);



						if(new_ip != 0) {
							update_iftable(&if_tab1, if_tab2.ifname[i], new_ip, &old_ip, 0, 0);
							reinstate_old_alias(&if_tab1, i, &if_tab2);
							check_for_session_break(&if_tab1, j, old_ip);//checks if sess.ft->iploc = old ip and assigns as alias ip
							do_break_before_make(if_tab2.ifname[i], old_ip, new_ip);

						}

					}
				}
		
			}
		}
	}


	//check for old interface missing: interface dropped
	for(unsigned i=0;i<if_tab1.nb_if;i++ ){//is there some IF in tab2 that's missing in tab1
		int found = 0;
		for(unsigned j=0;j<if_tab2.nb_if;j++) {
			if( strcmp(if_tab2.ifname[j], if_tab1.ifname[i]) == 0) found = 1;
		}

		if(!found) {//old interface missing
			old_ip = find_ipaddr(&if_tab1, if_tab1.ifname[i]);
			if(old_ip != 0) {
				sprintIPaddr(buf_ip_old, old_ip);
				sprintf(msg_buf, "handle_interface_changes: interface=%s with ipaddr=%s is down", if_tab1.ifname[i], buf_ip_old);
				add_msg(msg_buf);

				update_iftable(&if_tab1, if_tab1.ifname[i], 0, &old_ip, 0, 0);

				check_for_session_break(&if_tab1, i, old_ip);//checks if sess.ft->iploc = old ip and assigns as alias ip
				check_for_subflow_break(if_tab1.ifname[i], old_ip);//checks if active subflows are broken

				//copy all aliase of old interface to another interface thats up
				size_t ifup = find_iface_up(&if_tab1);
				if(ifup < if_tab1.nb_if) copy_alias_arrays(&if_tab1, i, ifup);
			}
		}
	}

}



//++++++++++++++++++++++++++++++++++++++++++++++++
//check_for_session_break(char * const ifname, const uint32_t old_ipaddr)
// this is used when ip address is discontinued
// checks if discontinued IP address is local session address
//++++++++++++++++++++++++++++++++++++++++++++++++
void check_for_session_break(struct if_table *iftab, size_t index, const uint32_t old_ipaddr){

	char buf_ip[34];
	sprintIPaddr(buf_ip, old_ipaddr);


	struct session *curr_sess, *tmp_sess;

	HASH_ITER(hh, sess_hash, curr_sess, tmp_sess) {
		
		if(curr_sess == NULL || curr_sess->ft.ip_loc != old_ipaddr)
			continue;

		sprintf(msg_buf,"check_for_session_break: ip address=%s found in sess_id=%zu", buf_ip, curr_sess->index);
		add_msg(msg_buf);

		//check if ipaddr is already in alias list. If not or if IF is down add old IP address to alias
		size_t tab_index;
		size_t alias_index;	

		int found = find_alias_ip(&if_tab1, old_ipaddr, &tab_index, &alias_index);

		if(!found) {

			if(iftab->ipaddr[index] != 0){
				add_alias_ip(&if_tab1, index, old_ipaddr);
			}			
			else{
				size_t ifup = find_iface_up(&if_tab1);
				if(ifup < if_tab1.nb_if) add_alias_ip(&if_tab1, ifup, old_ipaddr);
			}

		} else {
			sprintf(msg_buf,"check_for_session_break: ip address=%s found in sess_id=%zu, alias exists for IF=%s, id=%zu", 
				buf_ip, curr_sess->index, if_tab1.ifname[tab_index], alias_index);
			add_msg(msg_buf);

		}
	}//end HASH_ITER
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//if_tab1 contains alias in pointer array, if_tab2 explicitly
// checks if aliase in iftab1[index] are explicitly in iftab2
// if not they are added to iftab1
//++++++++++++++++++++++++++++++++++++++++++++++++
void reinstate_old_alias(struct if_table *iftab1, size_t index, struct if_table *iftab2) {

	for(unsigned i=0;i<iftab1->pAalias[index].number;i++) {
		char buf_ip[16];

		uint32_t* p_ip = (uint32_t*) get_pnt_pA(&iftab1->pAalias[index], i);
		sprintf(msg_buf,"reinstate_old_alias: reinstating ifname=%s:%u", 
					iftab1->ifname[index], i);

		int found = 0;
		for(unsigned j=0;j<iftab2->nb_if;j++) {
			if( strstr(iftab2->ifname[j], ":") != 0 && strstr(iftab2->ifname[j], iftab1->ifname[index]) != 0 ) found = 1;
		}
		if(!found) {

			sprintIPaddr(buf_ip, *p_ip);
			sprintf(msg_buf,"reinstate_old_alias: reinstating ifname=%s:%u, ipaddr=%s", 
					iftab1->ifname[index], i, buf_ip);
			add_msg(msg_buf);			
			create_alias(iftab1->ifname[index], i, *p_ip);
		}
	}
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//int find_alias_ip(struct if_table *iftab, uint32_t ipaddr, size_t *tab_index, size_t *alias_index)
//	returns 1, tab_index and alias_index if ipaddr is found among aliases; 0 otherwise
//	this is used to check if IP addr is already in alias list before adding it.
//++++++++++++++++++++++++++++++++++++++++++++++++
int find_alias_ip(struct if_table *iftab, uint32_t ipaddr, size_t *tab_index, size_t *alias_index) {
	size_t i,j;
	for(i=0; i<iftab->nb_if; i++) {
		for(j=0; j<iftab->pAalias[i].number; j++) {
			uint32_t* p_ip = (uint32_t*) get_pnt_pA(&iftab->pAalias[i], j);
			if(p_ip && *p_ip == ipaddr) {

				*tab_index = i;
				*alias_index = j;
				return 1;
			}
		}
	}
	return 0;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//void fix_alias_arrays(struct if_table *iftab, size_t size_t new_ target_index
//	finds all interfaces in if_table that are down and copies their aliases tointerface=iftab[target_index]
//++++++++++++++++++++++++++++++++++++++++++++++++
void fix_alias_arrays(struct if_table *iftab, size_t target_index) {
	size_t i;
	for(i=0;i<iftab->nb_if;i++) {
		if(i != target_index && iftab->ipaddr[i] == 0) copy_alias_arrays(iftab, i, target_index);

	}
	return;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//void copy_alias_arrays(struct if_table *iftab, size_t source_index, size_t target_index
//	copies all aliases from interface=iftab[source_index] to interface=iftab[target_index]
//	this is used to safe the alias IPs of an if that goes down
//	aliases on old interface are cleared automatically when interface goes down
//++++++++++++++++++++++++++++++++++++++++++++++++
void copy_alias_arrays(struct if_table *iftab, size_t source_index, size_t target_index) {

	sprintf(msg_buf, "copy_alias_arrays: copying alias arrays");
	add_msg(msg_buf);

	size_t i;
	if(source_index == target_index) return;

	for(i=0;i<iftab->pAalias[source_index].number;i++) {
		uint32_t* p_ip = (uint32_t*) get_pnt_pA(&iftab->pAalias[source_index], i);
		if(p_ip) add_alias_ip(iftab, target_index, *p_ip);
	}
	clear_pA(&iftab->pAalias[source_index]);
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//void add_alias_ip(struct if_tab *iftab, size_t index ifname, uint32_t ipaddr)
//	adds ipaddr as alias to interface = iftab[index]
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_alias_ip(struct if_table *iftab, size_t index, uint32_t ipaddr) {
	uint32_t *ip_alias = malloc(sizeof(uint32_t));
	*ip_alias = ipaddr;
	add_pnt_pA(&iftab->pAalias[index], (void*) ip_alias);

	create_alias(iftab->ifname[index], iftab->max_alias_index[index], ipaddr);
	iftab->max_alias_index[index]++;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//void create_alias_ip(char* ifname, size_t index, uint32_t ipaddr)
//	adds alias with index and ipaddr to interface
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_alias(char* ifname, size_t index, uint32_t ipaddr) {
	char cmd[50];
	strcpy(cmd, "ifconfig ");
	strcat(cmd, ifname);
	strcat(cmd,":");
	char nmb_str[25];
	sprintf(nmb_str,"%zu", index);
	strcat(cmd, nmb_str);
	strcat(cmd," ");
	sprintIPaddr(nmb_str, ipaddr);
	strcat(cmd, nmb_str);
	
	sprintf(msg_buf, "create_alias: cmd=%s", cmd);
	add_msg(msg_buf);
	system(cmd);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//void delete_alias_ip(struct if_tab *iftab, size_t index ifname, uint32_t ipaddr)
//	deletes ipaddr as alias to interface = iftab[index]
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_alias_entry(struct if_table *iftab, size_t tab_index, size_t alias_index) {

	//get IP address and then delete entry in table
	uint32_t *p_ip = (uint32_t*) get_pnt_pA(&iftab->pAalias[tab_index], alias_index);
	del_index_pA(&iftab->pAalias[tab_index], alias_index);

	//kill  alias
	char cmd[50];
	strcpy(cmd, "ifconfig ");
	strcat(cmd, iftab->ifname[tab_index]);
	strcat(cmd,":");
	char nmb_str[25];
	sprintf(nmb_str,"%zu", alias_index);
	strcat(cmd, nmb_str);
	strcat(cmd," ");
	sprintIPaddr(nmb_str, *p_ip);
	strcat(cmd, nmb_str);
	
	sprintf(msg_buf, "delete_alias_entry: cmd=%s", cmd);
	add_msg(msg_buf);
	system(cmd);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//void clean_aliases(struct if_tab *iftab)
//	cleans alias arrays
//++++++++++++++++++++++++++++++++++++++++++++++++
void clean_aliases(struct if_table *iftab) {
	sprintf(msg_buf, "clean_alias: cleaning aliases");
	add_msg(msg_buf);

	size_t i,j;
	int found;
	struct session *curr_sess, *tmp_sess;
	for(i=0; i<iftab->nb_if; i++) {
		for(j=0; j<iftab->pAalias[i].number; j++) {
			uint32_t *p_ip = (uint32_t*) get_pnt_pA(&iftab->pAalias[i], j);
					
			found = 0;
			HASH_ITER(hh, sess_hash, curr_sess, tmp_sess) {
				if(curr_sess != NULL && p_ip != NULL && curr_sess->ft.ip_loc == *p_ip)
					found = 1;
			}
			if(!found) delete_alias_entry(iftab, i,j);
		}
	}
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//void add_interface_to_table(iftab, ifname, new_ipaddr)
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_interface_to_table(struct if_table *iftab, char* ifname, uint32_t new_ipaddr) {
	strcpy(iftab->ifname[iftab->nb_if],ifname);
	iftab->ipaddr[iftab->nb_if] = new_ipaddr;
	clear_pA(&iftab->pAalias[iftab->nb_if]);
	iftab->nb_if++;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//update_if_table
// Adds IF name and IP address to table
// First checks if IF name is present
// ipaddr in host format
//returns: 0 no change. 1 ip address update. 2 new IF entry
//++++++++++++++++++++++++++++++++++++++++++++++++
int update_iftable(struct if_table *iftab, char * const ifname, const uint32_t new_ipaddr, uint32_t *pold_ipaddr, int clear_aliases, int include_aliases){
	
	static struct if_table *iftab1;
	iftab1 = iftab;

	*pold_ipaddr = 0;
	if(strncmp(ifname, "lo", 2) == 0) return 0; 
	if(strncmp(ifname, "dummy", 5) == 0) return 0;

	if(strlen(ifname) > MAX_LENGTH_IFACE_NAME){
		sprintf(msg_buf, "update_iftable: ifname = \"%s\" is too long!", ifname);
		add_msg(msg_buf);
		auxil_toggle('Q');
	}

	if(strstr(ifname,":") != 0) {

		if(clear_aliases) {

			char cmd[50];
			strcpy(cmd, "ifconfig ");
			strcat(cmd, ifname);
			strcat(cmd," down");
			sprintf(msg_buf, "update_iftable: cmd=%s", cmd);
			add_msg(msg_buf);

			strcat(cmd,"\n");
			system(cmd);

		}
		if(!include_aliases) return 0;
	}

	char buf_ip[16];
	sprintIPaddr(buf_ip, new_ipaddr);

	//if IF is already in table, update IP addr
	int found=-1;
	for(unsigned i=0;i<iftab->nb_if;i++) {
		if(strcmp(ifname, iftab->ifname[i]) == 0) {
			found=i;
			break;
		}
	}	


	if(found>-1) {//interface was found in table
		//check if new IP address matches that of other entries. If so, set them to 0
		for(unsigned i=0;i<iftab->nb_if;i++) {
			if(strcmp(ifname, iftab->ifname[i]) == 0 && found!=(int)i) {
				iftab->ipaddr[i] = 0;
			}
		}	

		//matching IP address
		if(new_ipaddr == iftab->ipaddr[found]) {
			return 0;
		}

		//new IP address for ifname
		*pold_ipaddr = iftab->ipaddr[found];
		iftab->ipaddr[found] = new_ipaddr;

		return 1;
	} else { //new ifname
		//check if any IP address matches that of other entries. If so, set them to 0
		for(unsigned i=0;i<iftab->nb_if;i++) {
			if(strcmp(ifname, iftab->ifname[i]) == 0) iftab->ipaddr[i] = 0;
		}	

		found = iftab->nb_if;
		if(found == MAX_INTERFACES && iftab == iftab1) {
			sprintf(msg_buf, "update_iftable: table is full!");
			add_msg(msg_buf);
			return 0;
		}

		add_interface_to_table(iftab, ifname, new_ipaddr);
		return 2;
	}
	return 0;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//size_t find_iface_up(struct if_table *iftab)
//	returns first interface in table that is up
//	if none is up, returns iftab.nb_if
//++++++++++++++++++++++++++++++++++++++++++++++++
size_t find_iface_up(struct if_table *iftab) {
	for(unsigned i=0; i<iftab->nb_if; i++) {
		if(iftab->ipaddr[i] != 0) return i;
	}
	return iftab->nb_if;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//int32_t find_other_ipaddr(uint32_t ipaddr): 
// finds another IP address than the one passed
// Returns 0 if none found
//++++++++++++++++++++++++++++++++++++++++++++++++
uint32_t find_other_ipaddr(struct if_table *iftab, uint32_t ipaddr) {

	//if IF is already in table (and not 127.0.0.1), update IP addr	
	int found=-1;
	for(unsigned i=0;i<iftab->nb_if;i++) {
		if(iftab->ipaddr[i] != ipaddr && iftab->ipaddr[i] != 2130706433 && iftab->ipaddr[i] != 0) {
			found=i;
			break;
		}
	}	
	//if not found, append	
	if(found==-1) {
		sprintf(msg_buf, "find_other_ipaddr: no other ipaddr found");
		add_msg(msg_buf);
		return 0;
	} else {
		char buf_ip[34];
		sprintIPaddr(buf_ip, iftab->ipaddr[found]);

		sprintf(msg_buf, "find_other_ipaddr: finds ipaddr=%s", buf_ip);
		add_msg(msg_buf);


		return iftab->ipaddr[found];
	}
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//find_interface
// Finds interface name based on IP address in table
// Returns 0 if not found, otherwise 1
// IP address in host format
//++++++++++++++++++++++++++++++++++++++++++++++++
int find_interface(struct if_table *iftab, char *ifname, const uint32_t ipaddr) {
	if(iftab->nb_if == 0) return 0;

	for(int i=0; i<MAX_INTERFACES; ++i) {
		if(iftab->ipaddr[i] == ipaddr) {
			strcpy(ifname, iftab->ifname[i]);
			return 1;
		}
	}
	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//find_ipaddr
// Finds ipaddr based on iface name in table
// Returns 0 if not found, otherwise ipaddr
// IP address in host format
//++++++++++++++++++++++++++++++++++++++++++++++++
uint32_t find_ipaddr(struct if_table *iftab, char *ifname) {
	if(iftab->nb_if == 0) return 0;

	for(int i=0; i<MAX_INTERFACES; ++i) {
		if(strcmp(iftab->ifname[i], ifname) == 0)
			return iftab->ipaddr[i];
	}
	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//void print_iptable()
//++++++++++++++++++++++++++++++++++++++++++++++++
void print_iptable(struct if_table *iftab) {

	for(unsigned i=0;i<iftab->nb_if;i++) {
		char buf_ip[16];
		sprintIPaddr(buf_ip, iftab->ipaddr[i]);
		sprintf(msg_buf, "print_iptable: finding ifname=%s, ipaddr=%s", iftab->ifname[i], buf_ip);
		add_msg(msg_buf);

		for(unsigned j=0; j<iftab->pAalias[i].number; j++) {

			uint32_t* p_ip = (uint32_t*) get_pnt_pA(&iftab->pAalias[i], j);

			sprintIPaddr(buf_ip, *p_ip);
			sprintf(msg_buf, "print_iptable: alias %s:%u, ipaddr=%s", iftab->ifname[i], j, buf_ip);
			add_msg(msg_buf);
		}
	}
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//Get local interfaces
// This determines all currently supported IP addresses
//++++++++++++++++++++++++++++++++++++++++++++++++
void load_host_info(struct if_table *iftab, int clear_aliases, int include_aliases) {

	struct ifaddrs *ifa;
	struct ifaddrs *local_ifaddrs;// = malloc(10*sizeof(struct ifaddrs*));
	if(getifaddrs(&local_ifaddrs) == -1){
		fprintf(stderr, "load_host_info: getting local_ifaddres returns error - terminating program\n");
		exit(1);
	}

	//clear if table
	iftab->nb_if=0;
		
	int family,s;
	ifa = (struct ifaddrs*) local_ifaddrs;
	char host[NI_MAXHOST];	
	for(;ifa;ifa = (struct ifaddrs*) ifa->ifa_next) {
		if(ifa->ifa_addr == NULL) continue;
		family = ifa->ifa_addr->sa_family;	
		if(family != AF_INET)
			continue;
	
		s = getnameinfo(ifa->ifa_addr,
			(family == AF_INET)? sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6),
			host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if(s!=0) {
			fprintf(stderr,"load_host_info: getnameinfo() failed: %s\n", gai_strerror(s));
			exit(1);
		}
		if( strcmp((char*) ifa->ifa_name, "lo") != 0) { // && strcmp( (char*) ifa->ifa_name, "dummy0") != 0){
			uint32_t old_addr;
			update_iftable(iftab, (char*) ifa->ifa_name, htonl(inet_addr(host)), &old_addr, clear_aliases, include_aliases);
		}

	}
	freeifaddrs(local_ifaddrs);
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//Upate_interfaces:
// Triggered when NETLINK socket receives messages
// Shows interface update
//++++++++++++++++++++++++++++++++++++++++++++++++
int update_interfaces(struct if_table *iftab, char **ifname, uint32_t *old_addr, uint32_t *new_addr) {

	int len;	    
	char buffer[4096];
	struct nlmsghdr *nlh;
	int ret=0;

	nlh = (struct nlmsghdr *)buffer;
	if((len = recv(nl_sd, nlh, 4096, 0)) > 0) {
	        while ((NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE)) {
	        	if (nlh->nlmsg_type == RTM_NEWADDR) {
			        struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);
			        struct rtattr *rth = IFA_RTA(ifa);
			        int rtl = IFA_PAYLOAD (nlh);

			        while (rtl && RTA_OK(rth, rtl)) {
			            if (rth->rta_type == IFA_LOCAL) {
			                uint32_t ipaddr = htonl(*((uint32_t *)RTA_DATA(rth)));
			                char name[IFNAMSIZ];
			                if_indextoname(ifa->ifa_index, name);
					//printf("update_interfaces: found interface=%s\n", name);
			
					*old_addr = find_ipaddr(iftab, name);
					//ret = update_iftable(iftab, name, ipaddr, old_addr, 0);
					strcpy(*ifname, name);
					*new_addr = ipaddr;
		 

			            }//end if
			            rth = RTA_NEXT(rth, rtl);
			        }//end while(rtl...
	       		}//end if
			nlh = NLMSG_NEXT(nlh, len);
		}//end while((NLMSG_OK...
	}

	return ret;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//Eval packet: Here the packet gets first
//++++++++++++++++++++++++++++++++++++++++++++++++
void eval_packet(uint32_t id, size_t hook, unsigned char *buf, u_int16_t len) {
	(void) len;

	//hook
	packd.id = id;
	packd.hook = hook;
	set_verdict(1,0,0);//init with accept: can be changed later	

	//buffer
	packd.buf = buf;

	//packet headers
	packd.pos_i4head = 0;	
	packd.ip4h = (struct ipheader*) (packd.buf+packd.pos_i4head);
	packd.tcph = (struct tcpheader*) (packd.buf+packd.pos_i4head+(packd.ip4h->ip_h1<<2));

	//Map headers on packet
	packd.totlen = ntohs(packd.ip4h->ip_len);
	packd.ip4len = (uint16_t) (packd.ip4h->ip_h1<<2);
	packd.pos_thead = packd.pos_i4head + packd.ip4len;
	packd.tcplen = (uint16_t) packd.tcph->th_off<<2;
	packd.pos_pay = packd.pos_thead + packd.tcplen;
	packd.paylen = packd.totlen - packd.ip4len - packd.tcplen;

	//new versions
	packd.flags = (uint8_t)(packd.tcph->th_flags);//flags	
	packd.syn = (packd.flags & 0x02)>>1;
	packd.ack = (packd.flags & 0x10)>>4;
	packd.fin = packd.flags & 0x01;
	packd.rst = (packd.flags & 0x04)>>2;


	//set fourtuple find session or subflow
	switch(packd.hook){

	case 1:{

			packd.fwd_type = M_TO_T;

			packd.ft.ip_loc = ntohl(packd.ip4h->ip_dst);
			packd.ft.ip_rem = ntohl(packd.ip4h->ip_src);
			packd.ft.prt_loc = ntohs(packd.tcph->th_dport);
			packd.ft.prt_rem = ntohs(packd.tcph->th_sport);

			HASH_FIND(hh, sfl_hash, &packd.ft, sizeof(struct fourtuple), packd.sfl);
			if(packd.sfl != NULL) {
				packd.sess = packd.sfl->sess;
			}
			else packd.sess = NULL;

		}
		break;
	case 3:{//hook == 3

			packd.fwd_type = T_TO_M;
		
			packd.ft.ip_loc = ntohl(packd.ip4h->ip_src);
			packd.ft.ip_rem = ntohl(packd.ip4h->ip_dst);
			packd.ft.prt_loc = ntohs(packd.tcph->th_sport);
			packd.ft.prt_rem = ntohs(packd.tcph->th_dport);

			HASH_FIND(hh, sess_hash, &packd.ft, sizeof(struct fourtuple), packd.sess);
			packd.sfl = NULL;

		}
		break;
	case 2:{//hook == 2

			packd.fwd_type = T_TO_M;

			//behaves like an output: packet arrives from TCP and is sent to subflow
			packd.ft.ip_loc = ntohl(packd.ip4h->ip_src);
			packd.ft.ip_rem = ntohl(packd.ip4h->ip_dst);
			packd.ft.prt_loc = ntohs(packd.tcph->th_sport);
			packd.ft.prt_rem = ntohs(packd.tcph->th_dport);

			//incoming TCP packet
			HASH_FIND(hh, sess_hash, &packd.ft, sizeof(struct fourtuple), packd.sess);
			packd.sfl = NULL;

			if(packd.sess != NULL) {
				break;
			}

			packd.fwd_type = M_TO_T;

			packd.ft.ip_loc = ntohl(packd.ip4h->ip_dst);
			packd.ft.ip_rem = ntohl(packd.ip4h->ip_src);
			packd.ft.prt_loc = ntohs(packd.tcph->th_dport);
			packd.ft.prt_rem = ntohs(packd.tcph->th_sport);

			//incoming MPTCP packet
			HASH_FIND(hh, sfl_hash, &packd.ft, sizeof(struct fourtuple), packd.sfl);
			if(packd.sfl != NULL) {
				packd.sess = packd.sfl->sess;
			}
			else packd.sess = NULL;

			break;
		}
		printf("sess =%lu\n", (long unsigned) packd.sess);
	}



	//find TPTCP options:start at tcpoptions.
	packd.nb_mptcp_options = parse_mptcp_options(buf+(packd.pos_thead)+20, (packd.tcplen)-20, mptopt);
	packd.mptcp_opt_len=0;//reset this value
	packd.tcp_options_compacted = 0;//reset this value
	packd.retransmit_flag = 0;
	buffer_tcp_header_checksum();//compuates & buffers checksum of tcp header only

	//reset dssopt_out
	memset(&dssopt_out, 0, sizeof(struct dss_option));

	//reset print_line
	if(PRINT_FILE) memset(&packd.prt_line, 0, sizeof(struct print_line));
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//insert_event: reinserts event
//++++++++++++++++++++++++++++++++++++++++++++++++
void insert_event(struct tp_event *evt, time_t dsec, suseconds_t dusec) {

	//retransmit time 
	gettimeofday(&evt->time, NULL);
	evt->time.tv_sec += dsec;
	evt->time.tv_usec += dusec;

	//put the whole thing on queue
	Insert(evt, PQ);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle event: sends event to the corresponding event-type handlers
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_event(struct tp_event *evt) {

	char state_str[20];		
	translate_event_state(evt->type, state_str);

	switch(evt->type){
	case RETRANSMIT: handle_rex_event(evt);
		break;
	case SESS_CLOSE: handle_sess_close_event(evt);
		break;
	case SFL_CLOSE: handle_sfl_close_event(evt);
		break;
	case SESS_BREAK: handle_sess_break_event(evt);
		break;
	case SFL_BREAK: handle_sfl_break_event(evt);
		break;
	case PRIO: handle_prio_event(evt);
		break;
	case REMOVE_ADDR: handle_remove_addr_event(evt);
		break;
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//check event queue: sends event to the corresponding event-type handlers
//++++++++++++++++++++++++++++++++++++++++++++++++
void check_event_queue() {

	//retransmit time 
	struct timeval now;
	gettimeofday(&now, NULL);

	//check if event is due. If it is or if it is NULL handle it.
	struct tp_event *ev = FindMin(PQ);

//	int count = 0;
	while( ev != NULL && is_due( ev, &now)) {

		handle_event(ev);
		DeleteMin(PQ);
		ev = FindMin(PQ);
	}
}


//callback function
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
               struct nfq_data *nfa, void *data) {
	(void)nfmsg;
	(void)data;

        u_int32_t id = 0;
        struct nfqnl_msg_packet_hdr *ph =
	       	nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
 

	unsigned char *payldata;
	unsigned char *payldata2; 
	int ret = nfq_get_payload(nfa, &payldata2);
	payldata = (unsigned char*) payldata2;

  	if (ret >= 0) {

		eval_packet(id, ph->hook, payldata, ret);
		mangle_packet(id);

		if(packd.data_update_flag == 1){
			if(packd.size_update_flag == 1 ) fix_checksums(packd.new_buf, packd.ip4len, packd.totlen);
			else fix_checksums(packd.buf, packd.ip4len, packd.totlen);
		}



	}	
  	unsigned char *new_data = (packd.size_update_flag)? packd.new_buf:packd.buf;

	int res;
	if(packd.data_update_flag) res = nfq_set_verdict(qh, id, packd.verdict, packd.totlen, new_data);
	else res = nfq_set_verdict(qh, id, packd.verdict, 0, NULL);

	if(res == -1) {
		sprintf(msg_buf, "nfq_set_verdict: id=%u creates erros", id);
		add_msg(msg_buf);
	}
	return res;
}


void run_loop() {
	 
	 fd_set fds_test;
	 fd_set fds_input;
	 FD_ZERO(&fds_input);		 
         FD_SET(nf_fd, &fds_input);
         FD_SET(nl_sd, &fds_input);
         FD_SET(fd_fifo_dwn, &fds_input);
	 fds_test = fds_input;
	 terminate_loop = 0;

	 sprintf(msg_buf,"run_loop: loading host table");
	 add_msg(msg_buf);
	 load_host_info(&if_tab1, 1, 0);//clears aliases
	 int i;
	 for(i=0;i<MAX_INTERFACES;i++) if_tab1.max_alias_index[i] = 0;
	 print_iptable(&if_tab1);//prints IP table to msg_Buf
         
         static int count=0;
 	 int rtn,fd,rv;

	 while(!terminate_loop) {
	 	rtn = select(FD_SETSIZE, &fds_test, (fd_set *) NULL, (fd_set *) NULL, (struct timeval*) NULL);

		if(rtn == -1) {
			fprintf(stderr,"select returns=%d, exit program!\n",rtn);	
			exit(1);
		}
		for(fd = 0; fd < FD_SETSIZE; fd++) {
			if(!FD_ISSET(fd, &fds_test))
				continue;

			if(fd == nf_fd) {
				check_event_queue();
				rv = recv(nf_fd, nf_buf, sizeof(nf_buf), 0);
				if(rv>=0) {
					count++;
					nfq_handle_packet(h, nf_buf, rv);
				}
			}

			if(fd == nl_sd) {
				handle_interface_changes();
			}

			if (fd == fd_fifo_dwn) {
				check_event_queue();
				check_fifo_msg();
			}
		}

		FD_CLR(nf_fd, &fds_input);
		FD_CLR(nl_sd, &fds_input);
		FD_CLR(fd_fifo_dwn, &fds_input);
		FD_SET(nf_fd, &fds_input);
		FD_SET(nl_sd, &fds_input);
		FD_SET(fd_fifo_dwn, &fds_input);
		fds_test = fds_input;

	}//end while(1)


} 


int main() {

	//init msg and file printing
	init_msg_data();
	if(PRINT_FILE) init_print_data();

	//seed random number generator
	srand(time(NULL));

	//clear tables
	clear_hash_tables();

	//init dummy interface	
//	init_dummy_iface();

	//start of iptables
	system("iptables -F");
	system("iptables -A INPUT -p tcp --tcp-flags SYN SYN -j QUEUE");
	system("iptables -A OUTPUT -p tcp --tcp-flags SYN SYN -j QUEUE");
	system("iptables -A FORWARD -p tcp --tcp-flags SYN SYN -j QUEUE");
	
	//setup of raw socket to send packets
	add_msg("setting up raw socket");
	raw_sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if(raw_sd<0) {
		fprintf(stderr, "couldn't open RAW socket\n");
		exit(1);
	}

	//setup or raw socket for NETLINK to report interface changes
	struct sockaddr_nl addr;
	nl_sd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if(nl_sd == -1) {
		fprintf(stderr, "couldn't open NETLINK_ROUTE socket\n");
		exit(1);
	}
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_IPV4_IFADDR;

	if(bind(nl_sd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "couldn't bind NETLINK_ROUTE\n");
		exit(1);
	}

	//make FIFOs
        add_msg("init FIFOs");
	init_fifos();

	//initialize PriorityQueue for event handling
	PQ = Initialize(HeapCapInc);

	//setup of netfilter queue
         add_msg("opening library handle");
         h = nfq_open();
         if(!h) {
                 fprintf(stderr, "error during nfq_open()\n");
                 exit(1);
         }
 
         add_msg("unbinding existing nf_queue handler for AF_INET (if any)");
         if(nfq_unbind_pf(h, AF_INET) < 0) {
                 fprintf(stderr, "error during nfq_unbind_pf()\n");
                 exit(1);
         }
 
         add_msg("binding nfnetlink_queue as nf_queue handler for AF_INET");
         if(nfq_bind_pf(h, AF_INET) < 0) {
                 fprintf(stderr, "error during nfq_bind_pf()\n");
                 exit(1);
         }
 
         add_msg("binding this socket to queue '0'");
         qh = nfq_create_queue(h,  0, &cb, NULL);
         if(!qh) {
                 fprintf(stderr, "error during nfq_create_queue()\n");
                 exit(1);
         }
 
         add_msg("setting copy_packet mode");
         if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
              fprintf(stderr, "can't set packet_copy mode\n");
                 exit(1);
         }

	if(nfq_set_queue_maxlen(qh, 8192) < 0) {
		fprintf(stderr,"error during extension of buffer size\n");
		exit(1);
	}

	nfnl_rcvbufsiz(nfq_nfnlh(h), 50000000);
        nf_fd = nfq_fd(h);

	add_msg("****STARTING MAIN LOOP****");

	//running main loop
	run_loop();

	add_msg("****TERMINATING MAIN LOOP****");

   
	delete_all_sessions();
 
	//unbinding from queue 0
         nfq_destroy_queue(qh);
 
#ifdef INSANE
         /* normally, applications SHOULD NOT issue this command, since
          * it detaches other programs/sockets from AF_INET, too ! */
         nfq_unbind_pf(h, AF_INET);
#endif
 
 	//flush iptables
	 system("iptables -F");

	//destroying all alias interfaces
	 sprintf(msg_buf,"deleting all alias interfaces\n");
	 add_msg(msg_buf);
	 load_host_info(&if_tab1, 1, 0);
	 clean_aliases(&if_tab1);

	 terminate_msg_data();
	 if(PRINT_FILE) terminate_print_data();

	 nfq_close(h);
         exit(0);
}

