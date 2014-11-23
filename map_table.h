//*****************************************************
//*****************************************************
//
// map_table.h 
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

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: create_map_entry
//++++++++++++++++++++++++++++++++++++++++++++++++
struct map_entry* create_map_entry(struct subflow *sfl, uint32_t dsn, uint32_t ssn, uint32_t range);

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: ssn_expand_entry
// entry is expanded by the ssn and range provided
//++++++++++++++++++++++++++++++++++++++++++++++++
void ssn_expand_entry(struct map_entry *entry, uint32_t ssn, uint32_t range);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: ssn_inside_entry
//	return -1,0,1 if ssn is below, inside or above entry
//++++++++++++++++++++++++++++++++++++++++++++++++
int ssn_inside_entry(struct map_entry *entry, uint32_t ssn);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: x_inside_entry
//	return -1,0,1 if x is below, inside or above entry
//	flag = 0: ssn, else dsn
//++++++++++++++++++++++++++++++++++++++++++++++++
int x_inside_entry(struct map_entry *entry, uint32_t xsn, int flag);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: ssn_inside_touch_entry
//	return -1,0,1 if ssn is below, inside or above entry
//	Inside means: its inside, or it touches and offset is the same
//++++++++++++++++++++++++++++++++++++++++++++++++
int ssn_inside_touch_entry(struct map_entry *entry, uint32_t ssn, uint32_t dsn);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: dsn_inside_touch_entry
//	return -1,0,1 if dsn is below, inside or above entry
//	Inside means: its inside, or it touches and offset is the same
//++++++++++++++++++++++++++++++++++++++++++++++++
int dsn_inside_touch_entry(struct map_entry *entry, uint32_t ssn, uint32_t dsn);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: dsn_expand_entry
// entry is expanded by the dsn and range provided
//++++++++++++++++++++++++++++++++++++++++++++++++
void dsn_expand_entry(struct map_entry *entry, uint32_t dsn, uint32_t range);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: dsn_inside_entry
//	return -1,0,1 if dsn is below, inside or above entry
//++++++++++++++++++++++++++++++++++++++++++++++++
int dsn_inside_entry(struct map_entry *entry, uint32_t dsn);

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: dsn_touch_entry
//	return -1,1 if dsn is touching below or above. 0 otherwise
//++++++++++++++++++++++++++++++++++++++++++++++++
int dsn_touch_entry(struct map_entry *entry, uint32_t dsn);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: prior_adjacent
//	returns 1 if prior entry is adjacent in ssn
//	returns 0 if prior entry does not exist or if not adjacent in ssn
//++++++++++++++++++++++++++++++++++++++++++++++++
int prior_adjacent_ssn(struct map_entry *entry);


//HERE COMES MAP TABLE
//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: init_map: Initializes pntArray
//++++++++++++++++++++++++++++++++++++++++++++++++
void init_map(struct map_table *map);

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: insert_first: inserts first element
//++++++++++++++++++++++++++++++++++++++++++++++++
void insert_first(struct  map_table *map, struct map_entry *entry);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: insert_behind: inserts entry behind pointer pnt1
//++++++++++++++++++++++++++++++++++++++++++++++++
void insert_behind(struct map_table *map, struct map_entry *entry);

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: insert_infront: inserts entry before pointer pnt1
//++++++++++++++++++++++++++++++++++++++++++++++++
void insert_infront(struct  map_table *map, struct map_entry *entry);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: delete_entry: deletes entry at pnt1
//pnt1 is then set at entry above
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_entry(struct map_table *map);

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: move_pnt_up: moves pnt1 up
//++++++++++++++++++++++++++++++++++++++++++++++++
int move_pnt_up(struct map_table *map);

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: move_pnt_dwn: moves pnt1 dwn
//++++++++++++++++++++++++++++++++++++++++++++++++
int move_pnt_dwn(struct map_table *map);

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: clear_map: deletes map
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_map(struct map_table *map);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: print map
//++++++++++++++++++++++++++++++++++++++++++++++++	
void print_map(struct map_table *map);

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: print packet
//++++++++++++++++++++++++++++++++++++++++++++++++	
void print_packet(uint32_t dsn, uint32_t ssn, uint32_t range);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: print entry
//++++++++++++++++++++++++++++++++++++++++++++++++	
void print_entry(struct map_table *map);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: enter_dsn_packet
//	enters dsn packet in a map ordered by ssn
///++++++++++++++++++++++++++++++++++++++++++++++++
int enter_dsn_packet(struct map_table *map, struct subflow *sfl, uint32_t dsn, uint32_t ssn, uint32_t range);


//++++++++++++++++++++++++++++++++++++++++++++++++
//void translate_SACK_output(): for output data, translates TCP SACK entries to SFL SACK entries
//	Only done if DO_SACK == 1 and DO_ACK_INFERENCE == 1
//	Starts at curr_san_rem and map->pnt3 both of which must have been set in find_SAN_SACK() before
//	curr_an_rem = max(SANrem_new, SAN_rem_sack); map->pnt3 points to entry that holds curr_an_rem
//	result will be buffered in Dsack_buf with counter nb_sack_buf
//++++++++++++++++++++++++++++++++++++++++++++++++
void translate_SACK_output(struct map_table *map, const uint32_t curr_an_rem, \
		const uint32_t* const sack, int nb_sack, uint32_t *sack_buf, int *nb_sack_buf);


//+++++++++++++++++++++++++++++++++++++++++++++
//add_to_sack_array
// 	adds [snLE, snRE] to sack_array; nb_sack is current number of sack entries
///++++++++++++++++++++++++++++++++++++++++++++++++
void add_to_sack_array(const uint32_t snL, const uint32_t snR, uint32_t *sack, int *nb_sack);


//+++++++++++++++++++++++++++++++++++++++++++++
//project_sack_space()
// 	projects sack entries contained in *sack in X-space to sack entries in Y space
//	based on map. If flag = 0, X = ssn and Y = dsn. If flag = 1, X = dsn and Y = ssn.
//	Flag = 0 is needed for INPUT and Flag = 1 for OUTPUT
//	First sack entry is old SAN-1 and new SAN-1 ( old DAN-1 and new DAN-1)
//	Algorithm assumes that table is sorted in X.
///+++++++++++++++++++++++++++++++++++++++++++++
int project_sack_space(struct map_table *map, const int nb_sack_in, uint32_t *sack_in, int *nb_sack_out, uint32_t *sack_out, uint32_t min_sack_out, int flag);



//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: enter_dsn_packet_on_top
// 	should be used to add dsn packet on top of map in case left edge of packet > highest_DSN
// 	If this condition does not apply, packet is a retransmission and the next following routines have to be used
///++++++++++++++++++++++++++++++++++++++++++++++++
void enter_dsn_packet_on_top(struct map_table *map, struct subflow * const sfl, const uint32_t dsn, const uint32_t ssn, const uint32_t range);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: find_entry_dsn_retransmit: finds entry for dsn retransmission
//	Should be used if dsn of packet is smaller than highest_dsn_loc
//	input: dsn, range
//	Finds entry to this dsn and returns sfl and ssn. Updates range (if entry's range is less than input range)
//	Sets pnt1 to this entry
//	If no entry exists for this dsn, returns sfl==NULL and range==0.
//	Sets pnt1 below and pnt2 above the emtpy spot
///++++++++++++++++++++++++++++++++++++++++++++++++
void find_entry_dsn_retransmit(struct map_table *const map, const uint32_t dsn, struct subflow **sfl, uint32_t *ssn, uint32_t *range);


//++++++++++++++++++++++++++++++++++++++++++++++++
//void find_DSN(): for input data, determines DSNrem based on map_recv and SSNrem
//++++++++++++++++++++++++++++++++++++++++++++++++
int find_DSN(uint32_t *DSNrem, struct map_table *map, uint32_t SSNrem);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: find_max_adjacent_ssn()
//	starts from bottom of table, finds max contiguous ssn
//	deletes all ssn below max_adjacent ssn
//	updates max_ssn. If table is empty, max_ssn is not updated
//++++++++++++++++++++++++++++++++++++++++++++++++
void find_max_adjacent_ssn(struct map_table *map, uint32_t *max_ssn);


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: delete_below_ssn
//	deletes all entries with RE below max_ssn
//	reduces the lowest entry to max_ssn
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_below_ssn(struct map_table *map, uint32_t max_ssn);

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: delete_below_dsn
//	deletes all entries with RE below max_dsn
//	reduces the lowest entry to max_dsn
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_below_dsn(struct map_table *map, uint32_t max_dsn);


