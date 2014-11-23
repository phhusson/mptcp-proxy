//*****************************************************
//*****************************************************
//
// mptcp_proxy.h 
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



struct iftab;


//++++++++++++++++++++++++++++++++++++++++++++++++
//clear hash tables
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void clear_hash_tables();


//++++++++++++++++++++++++++++++++++++++++++++++++
//subflow_IPtables: adds or deletes a subflow from IP tables
// 	add if add == 1 otherwise delete
//	ports and ip addreses in network notation
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void subflow_IPtables(
	char op, 
	int hook, 
	uint32_t ip_loc, 
	uint16_t prt_loc, 
	uint32_t ip_rem, 
	uint16_t prt_rem);


//++++++++++++++++++++++++++++++++++++++++++++++++
//void handle_interface_changes()
// Checks interface and ip address changes when trigger 
//  is received by select in run_loop()
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_interface_changes();


//++++++++++++++++++++++++++++++++++++++++++++++++
//check_for_session_break(char * const ifname, const uint32_t old_ipaddr)
// this is used when ip address is discontinued
// checks if discontinued IP address is local session address
//++++++++++++++++++++++++++++++++++++++++++++++++
void check_for_session_break(struct if_table *iftab, size_t index, const uint32_t old_ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//if_tab1 contains alias in pointer array, if_tab2 explicitly
// checks if aliase in iftab1[index] are explicitly in iftab2
// if not they are added to iftab1
//++++++++++++++++++++++++++++++++++++++++++++++++
void reinstate_old_alias(struct if_table *iftab1, size_t index, struct if_table *iftab2);


//++++++++++++++++++++++++++++++++++++++++++++++++
//int find_alias_ip(struct if_table *iftab, uint32_t ipaddr, size_t *tab_index, size_t *alias_index)
//	returns 1, tab_index and alias_index if ipaddr is found among aliases; 0 otherwise
//	this is used to check if IP addr is already in alias list before adding it.
//++++++++++++++++++++++++++++++++++++++++++++++++
int find_alias_ip(struct if_table *iftab, uint32_t ipaddr, size_t *tab_index, size_t *alias_index);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void fix_alias_arrays(struct if_table *iftab, size_t size_t new_ target_index
//	finds all interfaces in if_table that are down and copies their aliases tointerface=iftab[target_index]
//++++++++++++++++++++++++++++++++++++++++++++++++
void fix_alias_arrays(struct if_table *iftab, size_t target_index);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void copy_alias_arrays(struct if_table *iftab, size_t source_index, size_t target_index
//	copies all aliases from interface=iftab[source_index] to interface=iftab[target_index]
//	this is used to safe the alias IPs of an if that goes down
//	aliases on old interface are cleared automatically when interface goes down
//++++++++++++++++++++++++++++++++++++++++++++++++
void copy_alias_arrays(struct if_table *iftab, size_t source_index, size_t target_index);


//++++++++++++++++++++++++++++++++++++++++++++++++
//void add_alias_ip(struct if_tab *iftab, size_t index ifname, uint32_t ipaddr)
//	adds ipaddr as alias to interface = iftab[index]
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_alias_ip(struct if_table *iftab, size_t index, uint32_t ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void create_alias_ip(char* ifname, size_t index, uint32_t ipaddr)
//	adds alias with index and ipaddr to interface
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_alias(char* ifname, size_t index, uint32_t ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void delete_alias_entry(struct if_tab *iftab, size_t index ifname, uint32_t ipaddr)
//	deletes ipaddr as alias to interface = iftab[index]
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_alias_entry(struct if_table *iftab, size_t tab_index, size_t alias_index);


//++++++++++++++++++++++++++++++++++++++++++++++++
//void clean_aliases(struct if_tab *iftab)
//	cleans alias arrays
//++++++++++++++++++++++++++++++++++++++++++++++++
void clean_aliases(struct if_table *iftab);


//++++++++++++++++++++++++++++++++++++++++++++++++
//void add_interface_to_table(iftab, ifname, new_ipaddr)
//++++++++++++++++++++++++++++++++++++++++++++++++
void add_interface_to_table(struct if_table *iftab, char* ifname, uint32_t new_ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//load IF table entry
// Adds IF name and IP address to table
// First checks if IF name is present
//++++++++++++++++++++++++++++++++++++++++++++++++
int update_iftable(struct if_table *iftab, char * const ifname, const uint32_t new_ipaddr, uint32_t *pold_ipaddr, int clear_aliases, int include_aliases);

//++++++++++++++++++++++++++++++++++++++++++++++++
//size_t find_iface_up(struct if_table *iftab)
//	returns first interface in table that is up
//	if none is up, returns iftab.nb_if
//++++++++++++++++++++++++++++++++++++++++++++++++
size_t find_iface_up(struct if_table *iftab);


//++++++++++++++++++++++++++++++++++++++++++++++++
//int32_t find_other_ipaddr(uint32_t ipaddr): 
// finds another IP address than the one passed
// Returns 0 if none found
//++++++++++++++++++++++++++++++++++++++++++++++++
uint32_t find_other_ipaddr(struct if_table *iftab, uint32_t ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//find_interface
// Finds interface name based on IP address in table
// Returns 0 if not found, otherwise 1
// IP address in host format
//++++++++++++++++++++++++++++++++++++++++++++++++
int find_interface(struct if_table *iftab, char *ifname, const uint32_t ipaddr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//find_ipaddr
// Finds ipaddr based on iface name in table
// Returns 0 if not found, otherwise ipaddr
// IP address in host format
//++++++++++++++++++++++++++++++++++++++++++++++++
uint32_t find_ipaddr(struct if_table *iftab, char *ifname);

//++++++++++++++++++++++++++++++++++++++++++++++++
//void print_iptable()
//++++++++++++++++++++++++++++++++++++++++++++++++
void print_iptable(struct if_table *iftab);

//++++++++++++++++++++++++++++++++++++++++++++++++
//Get local interfaces
// This determines all currently supported IP addresses
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void load_host_info(struct if_table *iftab, int clear_aliases, int include_aliases);

//++++++++++++++++++++++++++++++++++++++++++++++++
//Upate_interfaces:
// Triggered when NETLINK socket receives messages
// Shows interface update
//++++++++++++++++++++++++++++++++++++++++++++++++
int update_interfaces(struct if_table *iftab, char **ifname, uint32_t *old_addr, uint32_t *new_addr);

//++++++++++++++++++++++++++++++++++++++++++++++++
//Eval packet: Here the packet gets first
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void eval_packet(uint32_t id, size_t hook, unsigned char *buf, u_int16_t len);


//++++++++++++++++++++++++++++++++++++++++++++++++
//reinsert_event: reinserts event
//++++++++++++++++++++++++++++++++++++++++++++++++
void insert_event(struct tp_event *evt, time_t dsec, suseconds_t dusec);


//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_event: sends event to the corresponding event-type handlers
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_event(struct tp_event *evt);

//++++++++++++++++++++++++++++++++++++++++++++++++
//check event queue: sends event to the corresponding event-type handlers
//++++++++++++++++++++++++++++++++++++++++++++++++
void check_event_queue();

