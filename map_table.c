//*****************************************************
//*****************************************************
//
// map_table.c 
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
#include "map_table.h"


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: create_map_entry
//++++++++++++++++++++++++++++++++++++++++++++++++
struct map_entry* create_map_entry(struct subflow *sfl, uint32_t dsn, uint32_t ssn, uint32_t range) {

	struct map_entry *entry = malloc(sizeof(struct map_entry));
	entry->sfl = sfl;
	entry->dsn = dsn;
	entry->ssn = ssn;
	entry->range = range;
	entry->next = NULL;
	entry->prior = NULL;
	return entry;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: ssn_expand_entry
// entry is expanded by the ssn and range provided
//++++++++++++++++++++++++++++++++++++++++++++++++
void ssn_expand_entry(struct map_entry *entry, uint32_t ssn, uint32_t range) {

	if(entry == NULL) return;

	//left edge
	if(sn_smaller(ssn, entry->ssn)) {
		uint32_t offset = entry->dsn - entry->ssn;//buffer offset
		entry->range += (entry->ssn - ssn);//expand entry->range since entry->ssn is reduced
		entry->ssn = ssn;//reduce entry->ssn
		entry->dsn = entry->ssn + offset;//update entry ->dsn
	}

	//right edge
	if(sn_smaller(entry->ssn + entry->range, ssn + range))
		entry->range = ssn + range - entry->ssn; 

	 	
	return;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: ssn_inside_entry
//	return -1,0,1 if ssn is below, inside or above entry
//++++++++++++++++++++++++++++++++++++++++++++++++
inline int ssn_inside_entry(struct map_entry *entry, uint32_t ssn) {

	if( sn_smaller(ssn,entry->ssn)) return -1;
	if( sn_smaller_equal(entry->ssn + entry->range, ssn)) return 1;
	return 0;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: x_inside_entry
//	return -1,0,1 if x is below, inside or above entry
//	flag = 0: ssn, else dsn
//++++++++++++++++++++++++++++++++++++++++++++++++
inline int x_inside_entry(struct map_entry *entry, uint32_t xsn, int flag) {
	if(!flag) {
		if( sn_smaller(xsn,entry->ssn)) return -1;
		if( sn_smaller_equal(entry->ssn + entry->range, xsn)) return 1;
		return 0;
	}

	if( sn_smaller(xsn, entry->dsn)) return -1;
	if( sn_smaller_equal(entry->dsn + entry->range, xsn)) return 1;
	return 0;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: ssn_inside_touch_entry
//	return -1,0,1 if ssn is below, inside or above entry
//	Inside means: its inside, or it touches and offset is the same
//++++++++++++++++++++++++++++++++++++++++++++++++
inline int ssn_inside_touch_entry(struct map_entry *entry, uint32_t ssn, uint32_t dsn) {

	//check offset match
	int offset =( dsn - ssn == entry->dsn - entry->ssn)? 1 : 0;

	//below
	if( sn_smaller(ssn, entry->ssn - offset)) return -1;

	//above
	if( sn_smaller_equal(entry->ssn + entry->range + offset, ssn)) return 1;

	//inside		
	return 0;

}

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: dsn_inside_touch_entry
//	return -1,0,1 if dsn is below, inside or above entry
//	Inside means: its inside, or it touches and offset is the same
//++++++++++++++++++++++++++++++++++++++++++++++++
inline int dsn_inside_touch_entry(struct map_entry *entry, uint32_t ssn, uint32_t dsn) {

	//check offset match
	int offset =( dsn - ssn == entry->dsn - entry->ssn)? 1:0;

	//below
	if( sn_smaller(dsn, entry->dsn - offset)) return -1;

	//above
	if( sn_smaller_equal(entry->dsn + entry->range + offset, dsn)) return 1;

	//inside		
	return 0;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: dsn_expand_entry
// entry is expanded by the dsn and range provided
//++++++++++++++++++++++++++++++++++++++++++++++++
void dsn_expand_entry(struct map_entry *entry, uint32_t dsn, uint32_t range) {

	if(entry == NULL)
		return;

	//left edge
	if(sn_smaller(dsn, entry->dsn)) {
		uint32_t offset = entry->dsn - entry->ssn;//buffer offset
		entry->range += (entry->dsn - dsn);//expand entry->range since entry->dsn is reduced
		entry->dsn = dsn;//reduce entry->ssn
		entry->ssn = entry->dsn - offset;//update entry ->dsn
	}

	//right edge
	if(sn_smaller(entry->dsn + entry->range, dsn + range))
		entry->range = dsn + range - entry->dsn; 
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: dsn_inside_entry
//	return -1,0,1 if dsn is below, inside or above entry
//++++++++++++++++++++++++++++++++++++++++++++++++
inline int dsn_inside_entry(struct map_entry *entry, uint32_t dsn) {
	if( sn_smaller(dsn,entry->dsn)) return -1;
	if( sn_smaller_equal(entry->dsn + entry->range, dsn)) return 1;
	return 0;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: dsn_touch_entry
//	return -1,1 if dsn is touching below or above. 0 otherwise
//++++++++++++++++++++++++++++++++++++++++++++++++
inline int dsn_touch_entry(struct map_entry *entry, uint32_t dsn) {
	if( dsn == entry->dsn-1) return -1;
	if( dsn == entry->dsn + entry->range ) return 1;
	return 0;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: prior_adjacent
//	returns 1 if prior entry is adjacent in ssn
//	returns 0 if prior entry does not exist or if not adjacent in ssn
//++++++++++++++++++++++++++++++++++++++++++++++++
inline int prior_adjacent_ssn(struct map_entry *entry) {
	if(entry->prior != NULL && entry->ssn + entry->range == entry->prior->ssn)
		return 1;
	return 0;
}




//HERE COMES MAP TABLE
//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: init_map: Initializes pntArray
//++++++++++++++++++++++++++++++++++++++++++++++++
void init_map(struct map_table *map) {
	map->size = 0;
	map->top = NULL;
	map->bot = NULL;
	map->pnt1 = NULL;
	map->pnt2 = NULL;
	map->pnt3 = NULL;
	return;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: insert_first: inserts first element
//++++++++++++++++++++++++++++++++++++++++++++++++
void insert_first(struct  map_table *map, struct map_entry *entry) {
	map->size = 1;
	map->top = entry;
	map->bot = entry;
	map->pnt1 = entry;
	map->pnt2 = entry;
	map->pnt3 = entry;
	entry->next = NULL;
	entry->prior = NULL;
	return;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: insert_behind: inserts entry behind pointer pnt1
//++++++++++++++++++++++++++++++++++++++++++++++++
void insert_behind(struct map_table *map, struct map_entry *entry) {
	if(entry == NULL) return;

	if(map->size == 0) insert_first(map, entry);
	else {
		entry->next = map->pnt1->next;
		entry->prior = map->pnt1;
		if(entry->next == NULL) map->bot = entry;
		else entry->next->prior = entry;
		entry->prior->next = entry;
		map->size++;
	}
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: insert_infront: inserts entry before pointer pnt1
//++++++++++++++++++++++++++++++++++++++++++++++++
void insert_infront(struct  map_table *map, struct map_entry *entry) {
	if(entry == NULL) return;
	if(map->size == 0) insert_first(map, entry);
	else {
		entry->prior = map->pnt1->prior;
		entry->next = map->pnt1;
		if(entry->prior == NULL) map->top = entry;
		else entry->prior->next = entry;
		entry->next->prior = entry;
		map->size++;
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: delete_entry: deletes entry at pnt1
//pnt1 is then set at entry above
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_entry(struct map_table *map) {

	if(map->pnt1 == NULL || map->size == 0) return;

	if(map->pnt1->prior != NULL) {
		map->pnt1->prior->next = map->pnt1->next;
		if(map->pnt1->next == NULL) map->bot = map->pnt1->prior;
	}

	if(map->pnt1->next != NULL) {
		map->pnt1->next->prior = map->pnt1->prior;
		if(map->pnt1->prior == NULL) map->top = map->pnt1->next;
	}	

	struct map_entry *temp = map->pnt1;//set temp to the entry that will be deleted
	//set pnt1 to higher element. if null set to lower element
	if(map->pnt1->prior != NULL) map->pnt1 = map->pnt1->prior;//set pnt1 to higher element
	else{ 
		if (map->pnt1->next != NULL) map->pnt1 = map->pnt1->next;
		else map->pnt1 = NULL;
	}

	if(map->pnt2 == temp) map->pnt2 = map->pnt1;	
	if(map->pnt3 == temp) map->pnt3 = map->pnt1;


	if(temp != NULL) {
		free(temp);
		map->size--;
	}

	if(map->size == 0) init_map(map);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: move_pnt_up: moves pnt1 up
//++++++++++++++++++++++++++++++++++++++++++++++++
int move_pnt_up(struct map_table *map) {

	if(map->pnt1->next == NULL) return 0;

	map->pnt1 = map->pnt1->next;
	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: move_pnt_dwn: moves pnt1 dwn
//++++++++++++++++++++++++++++++++++++++++++++++++
int move_pnt_dwn(struct map_table *map) {

	if(map->pnt1->prior == NULL) return 0;

	map->pnt1 = map->pnt1->prior;
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: clear_map: deletes map
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_map(struct map_table *map) {

	map->pnt1 = map->top;
	struct map_entry *temp = map->pnt1;
	
	while(temp != NULL){
		temp = map->pnt1->next;		
		free(map->pnt1);
		map->pnt1 = temp;
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: print map
//++++++++++++++++++++++++++++++++++++++++++++++++	
void print_map(struct map_table *map) {
	map->pnt1 = map->top;
	printf("print_map:\n");

	while(map->pnt1 != NULL){
		printf("map: sfl=%lu, dsn_L=%lu, dsn_R=%lu, ssn_L=%lu, ssn_R=%lu, off=%lu, range=%lu\n",
			(long unsigned) map->pnt1->sfl,
			(long unsigned) map->pnt1->dsn, (long unsigned) map->pnt1->dsn + map->pnt1->range - 1,
			(long unsigned) map->pnt1->ssn, (long unsigned) map->pnt1->ssn + map->pnt1->range - 1,
			(long unsigned) map->pnt1->dsn - map->pnt1->ssn,
			(long unsigned) map->pnt1->range);
		map->pnt1 = map->pnt1->next;
	}
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: print packet
//++++++++++++++++++++++++++++++++++++++++++++++++	
void print_packet(uint32_t dsn, uint32_t ssn, uint32_t range) {
	printf("packet: dsn=%lu, ssn_L=%lu, ssn_R=%lu, off=%lu, range=%lu\n",
		(long unsigned) dsn, 
		(long unsigned) ssn, (long unsigned) ssn + range - 1,
		(long unsigned) dsn - ssn,
		(long unsigned) range);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: print entry
//++++++++++++++++++++++++++++++++++++++++++++++++
void print_entry(struct map_table *map) {
	if(map->pnt1 == NULL) {
		 printf("entry = 0\n\n");
		return;
	}

	printf("entry: sfl_id=%zu, dsn=%lu, ssn_L=%lu, ssn_R=%lu, off=%lu, range=%lu\n",
		map->pnt1->sfl->index,
		(long unsigned) map->pnt1->dsn, 
		(long unsigned) map->pnt1->ssn, (long unsigned) map->pnt1->ssn + map->pnt1->range - 1,
		(long unsigned) map->pnt1->dsn - map->pnt1->ssn,
		(long unsigned) map->pnt1->range);
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: enter_dsn_packet
//	enters dsn packet in a map ordered by ssn
//	returns: 0 packet above contigous, 1: packet above with gap,2: all other cases
///++++++++++++++++++++++++++++++++++++++++++++++++
int enter_dsn_packet(struct map_table *map, struct subflow *sfl, uint32_t dsn, uint32_t ssn, uint32_t range) {
	int res;
	if(map->top != NULL) {
		//special treatment for new packet arriving in order
		res = dsn_inside_touch_entry(map->top, ssn, dsn);
		if(res == 0) {//left edge of packet inside or contiguous
			dsn_expand_entry(map->top, dsn, range);
			map->pnt1 = map->top;
			return 0;
		}
		if(res == 1) {//left edge of packet is above and not contiguous
			struct map_entry *entry = create_map_entry(sfl, dsn, ssn, range);//new entry
			map->pnt1 = map->top;
			insert_infront(map, entry);
			return 1;
		}

		//all other cases
		//set pnt1 to top. move pnt1 down if right edge of packet is below pnt1
		map->pnt1 = map->top;
		while(map->pnt1 != NULL &&
				dsn_inside_touch_entry(map->pnt1, ssn+range-1, dsn+range-1) == -1) 
			map->pnt1 = map->pnt1->next;

		//enter packet
		int res;
		struct map_entry *entry;
		if(map->pnt1 == NULL) {
			entry = create_map_entry(sfl, dsn, ssn, range);//new entry on bottom
			map->pnt1 = map->bot;
			insert_behind(map, entry);

		} else {
			res = dsn_inside_touch_entry(map->pnt1, ssn +range-1, dsn+range-1);
			if (res == 1){//right edge of packet falls into gap
				entry = create_map_entry(sfl, dsn, ssn, range);//create new entry above entry
				insert_infront(map, entry);
			} else {//right edge of packet falls into entry
				entry = map->pnt1;//keep entry and expand based on packet
				dsn_expand_entry(map->pnt1, dsn, range);
			}
		}
 
		//merge entry downwards
		map->pnt1 = entry;
		uint32_t sre = 0, dre = 0;

		if(map->pnt1->next != NULL) { 
			sre = map->pnt1->next->ssn + map->pnt1->next->range -1;//right edge ssn of next entry
			dre = map->pnt1->next->dsn + map->pnt1->next->range -1;//right edge dsn of next entry
		}

		while(map->pnt1->next != NULL && dsn_inside_touch_entry(map->pnt1, sre, dre) > -1) {

			//expand entry with the envelop of entry and entry->next;
			dsn_expand_entry(map->pnt1, map->pnt1->next->dsn, map->pnt1->next->range);
	
			//move down and delete
			map->pnt1 = map->pnt1->next;
			delete_entry(map);//deletes map->pnt1 and sets map->pnt1 to the entry above

			//set new right edge	
			if(map->pnt1->next != NULL) { 
				sre = map->pnt1->next->ssn + map->pnt1->next->range -1;//right edge ssn of next entry
				dre = map->pnt1->next->dsn + map->pnt1->next->range -1;//right edge dsn of next entry
			}
		}	

		return 2;
	}

	//if this is the first entry
	struct map_entry *entry = create_map_entry(sfl, dsn, ssn, range);//new entry
	map->pnt1 = map->top;
	insert_infront(map, entry);	
	return 2;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//void translate_SACK_output(): for output data, translates TCP SACK entries to SFL SACK entries
//	Only done if DO_SACK == 1 and DO_ACK_INFERENCE == 1
//	Starts at curr_san_rem and map->pnt3 both of which must have been set in find_SAN_SACK() before
//	curr_an_rem = max(SANrem_new, SAN_rem_sack); map->pnt3 points to entry that holds curr_an_rem
//++++++++++++++++++++++++++++++++++++++++++++++++
void translate_SACK_output(struct map_table *map, const uint32_t curr_an_rem,
		const uint32_t* const sack, int nb_sack, uint32_t *sack_buf, int *nb_sack_buf) {

	*nb_sack_buf = 0;
	struct map_entry *e = map->pnt3;

	int i, low, high;
	uint32_t off;
	while(e!= NULL && *nb_sack_buf < MAX_SACK_BUF_ENTRIES) {
		i = 0;
		off = e->dsn - e->ssn;
		//loop overall sack entries as long as neither sack edge fits into entry and sack bock does not envelope entry 
		for(i=0;i<nb_sack;i++) {
			low = dsn_inside_entry(e, sack[(i<<1)]);
			high = dsn_inside_entry(e, sack[(i<<1)+1]);

			if( low == 0) { //lower edge falls into entry, higher edge might fall into entry

				if(sn_smaller(curr_an_rem-1, sack[(i<<1)] - off )) {
					//buffer DSN sack values
					*( sack_buf + ((*nb_sack_buf)<<1) ) = sack[(i<<1)] - off;
					*( sack_buf + ((*nb_sack_buf)<<1)+1) = sack[(i<<1)+1] - off;			
					if(sn_smaller(e->dsn + e->range - 1, sack[(i<<1)+1])) \
							*( sack_buf + *nb_sack_buf + 1) = e->dsn + e->range -1 - off;
					*nb_sack_buf+=1;
					i = nb_sack;
				}
			} else {//lower edge does not fall into entry
				if( high == 0 &&
						sn_smaller(curr_an_rem-1, sack[(i<<1)] - off)) {//higher edge falls into entry

					//buffer DSN sack values
					*( sack_buf + ((*nb_sack_buf)<<1) ) = e->dsn - off;
					*( sack_buf + ((*nb_sack_buf)<<1)+1) = sack[(i<<1)+1] - off;			
					*nb_sack_buf+=1;
					i = nb_sack;
				}		
			}
			if(low == -1 && high == 1 &&
					sn_smaller(curr_an_rem-1, sack[(i<<1)] - off)) {//envelope
				*( sack_buf + ((*nb_sack_buf)<<1) ) = e->dsn - off;
				*( sack_buf + ((*nb_sack_buf)<<1) + 1) = e->dsn + e->range -1 - off;
				*nb_sack_buf+=1;
				i = nb_sack;
			}
		};

		e = e->prior;
	}
}


//+++++++++++++++++++++++++++++++++++++++++++++
//add_to_sack_array
// 	adds [snLE, snRE] to sack_array; nb_sack is current number of sack entries
///++++++++++++++++++++++++++++++++++++++++++++++++
void add_to_sack_array(const uint32_t snL, const uint32_t snR, uint32_t *sack, int *nb_sack) {

	if(snL == snR) return;

	//short cut for first entry
	if(*nb_sack == 0) {
		sack[0] = snL;
		sack[1] = snR;
		*nb_sack = 1;
		return;
	}

	//find highest sack block index completetly below snL
	int j = -1;
	while(j+1 < *nb_sack && sn_smaller(sack[( (j+1)<<1) + 1]+1, snL) ) j++;//find sack block with RE below snL
	//find lowest sack block index completetly above snR
	int k = j+1;
	while(k < *nb_sack && sn_smaller_equal(sack[(k<<1)]-1, snR)) k++;//Left edge of sack moved below right edge Y

	if(k == j+1 ) {//add new sack entry at k= j+1 and move entrie from k to nb_sack one up
		if( *nb_sack < MAX_SACK_BUF_ENTRIES) {
			if(k < *nb_sack) { 
				 memmove( (unsigned char*) (sack + ((k+1)<<1) ), (unsigned char*) (sack + (k<<1)), (*nb_sack - k)<<3 );
			}
			(*nb_sack)++;
		}
		sack[(k<<1)] = snL;
		sack[(k<<1)+1] = snR;

	} else {//merge sack entries from j+1 to k-1 and overlap with [snL, snR]. Move entries above k-1 down by (k-1) -(j+1) to j+2
		j++;
		k--;
		if( sn_smaller(snL, sack[j<<1])) sack[j<<1] = snL;
		sack[(j<<1)+1] = sack[(k<<1)+1];
		if( sn_smaller( sack[(j<<1)+1], snR )) sack[(j<<1)+1] = snR;
		memmove( (unsigned char*) (sack + ((j+1)<<1)), (unsigned char*) (sack + ((k+1)<<1)), ((*nb_sack)-(k+1))<<3 );		
		(*nb_sack) -= (k - j);
	}
}


//+++++++++++++++++++++++++++++++++++++++++++++
//project_sack_space()
// 	projects sack entries contained in *sack in X-space to sack entries in Y space
//	based on map. If flag = 0, X = ssn and Y = dsn. If flag = 1, X = dsn and Y = ssn.
//	Flag = 0 is needed for INPUT and Flag = 1 for OUTPUT
//	First sack entry is old SAN-1 and new SAN-1 ( old DAN-1 and new DAN-1)
//	Algorithm assumes that table is sorted in X.
///+++++++++++++++++++++++++++++++++++++++++++++
int project_sack_space(struct map_table *map, const int nb_sack_in, uint32_t *sack_in,
		int *nb_sack_out, uint32_t *sack_out, uint32_t min_sack_out, int flag) {

	*nb_sack_out = 0;
	
	//This is INPUT.
	//ensure that first sack_in value is in pnt2 entry
	if(map->size == 0) return 0;
	if(map->pnt2 == NULL) map->pnt2 = map->top;

	struct map_entry *e2;
	struct map_entry *e1 = map->pnt2;

	//ensure that old value is inside e1 or in gap below e1
	//move down as long as old value below e1 and not above e1->next
	while( x_inside_entry(e1, *sack_in, flag) == -1 && e1->next != NULL  && x_inside_entry(e1->next, *sack_in, flag) != 1)  e1 = e1->next;

	//move up if old value is above e1
	//this is done in for loop
	
	//loop over sack_in elements
	int i1;
	uint32_t left_y, right_y;
	for(i1 = 0; i1 < nb_sack_in; i1++) {

		//move up until x1 is inside entry or in gap below entry
		while( x_inside_entry(e1, *(sack_in + (i1<<1)), flag) > 0 && e1->prior) e1 = e1->prior;
		if(x_inside_entry(e1, *(sack_in + (i1<<1)), flag) > 0 && !e1->prior) break;

		//if x inside entry: y = LY + x1 - LX
		if( x_inside_entry(e1, *(sack_in + (i1<<1)), flag ) == 0) {
			left_y = ((flag)? e1->ssn:e1->dsn) + *(sack_in+(i1<<1)) - ((flag)? e1->dsn:e1->ssn);
		}
		else left_y = (flag)? e1->ssn:e1->dsn;//else y = LY
		
		//find entry that overlaps with x2
		e2 = e1;
		while( x_inside_entry(e2, *(sack_in + (i1<<1) +1), flag ) > 0) {
					
			right_y = ( (flag)? e2->ssn:e2->dsn ) + e2->range - 1;//y = RY
			if( sn_smaller(min_sack_out, right_y)) add_to_sack_array(left_y, right_y, sack_out, nb_sack_out);//automatically increments nb_sack_out
			if(i1 == 0) map->pnt2 = e2;

			e2 = e2->prior;
			if( e2 ) left_y = (flag)? e2->ssn:e2->dsn; //set new left_y value to left edge of entry
			else break;
		} 
		if(!e2) break;

		//if x2 inside entry: y = LY + x2 - LX
		if( x_inside_entry(e2, *(sack_in + (i1<<1) +1), flag ) == 0) {
			right_y = ( (flag)? e2->ssn:e2->dsn ) + *(sack_in+(i1<<1)+ 1) - ((flag)? e2->dsn:e2->ssn) ;
			if( sn_smaller(min_sack_out, right_y)) add_to_sack_array(left_y, right_y, sack_out, nb_sack_out);//automatically increments nb_sack_out
			if(i1 == 0) map->pnt2 = e2;
		}

	}

	if(*nb_sack_out == 0) {

		sack_out[0] = min_sack_out;
		sack_out[1] = min_sack_out;
		*nb_sack_out = 1;
	}
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: enter_dsn_packet_on_top
// 	should be used to add dsn packet on top of map in case left edge of packet > highest_DSN
// 	If this condition does not apply, packet is a retransmission and the next following routines have to be used
///++++++++++++++++++++++++++++++++++++++++++++++++
void enter_dsn_packet_on_top(struct map_table *map, struct subflow * const sfl,
		const uint32_t dsn, const uint32_t ssn, const uint32_t range) {

	if(map->top != NULL && dsn_touch_entry(map->top, dsn) == 1
			&& sfl == map->top->sfl && (map->top->dsn - map->top->ssn) == (dsn - ssn)) {//same subflow and same offset
		dsn_expand_entry(map->top, dsn, range);
		return;				
	}		


	//if this is the first entry
	struct map_entry *entry = create_map_entry(sfl, dsn, ssn, range);//new entry
	map->pnt1 = map->top;
	insert_infront(map, entry);	
	return;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//map_entry: find_entry_dsn_retransmit: finds entry for dsn retransmission
//	Should be used if dsn of packet is smaller than highest_dsn_loc (on output)
//	input: dsn
//	Finds entry to this dsn and returns sfl, ssn and range available for this dsn.
//	Table is assumed to be ordered with respect to dsn.
//	If no entry exists for this dsn, returns sfl==NULL and sets range to the space available until next entry (infinity = 999999)
///++++++++++++++++++++++++++++++++++++++++++++++++
void find_entry_dsn_retransmit(struct map_table *const map, const uint32_t dsn, struct subflow **sfl, uint32_t *ssn, uint32_t *range) {

	//set pnt1 to top. move pnt1 down if left edge of packet is below pnt1 entry.
	//Finally pnt1 entry will be NULL or edge will be inside pnt1 entry or above.
	map->pnt1 = map->top;
	while(map->pnt1 != NULL && ( dsn_inside_entry(map->pnt1, dsn) != 0 )) map->pnt1 = map->pnt1->next;

	//If pnt1=NULL, bottom was reached. This means that there's s no entry for this packet.
	if(map->pnt1 == NULL) {
		*sfl = NULL;
		*ssn = 0;
		*range = 0;

		return;
	}

	//what remains is: left edge of packet is inside pnt1 entry
	*sfl = map->pnt1->sfl;
	*ssn = map->pnt1->ssn + dsn - map->pnt1->dsn;
	*range = map->pnt1->dsn + map->pnt1->range - dsn;
}


		
//++++++++++++++++++++++++++++++++++++++++++++++++
//void find_DSN(): for input data, determines DSNrem based on map_recv and SSNrem
//++++++++++++++++++++++++++++++++++++++++++++++++
int find_DSN(uint32_t *DSNrem, struct map_table *map, uint32_t SSNrem) {

	//if there are not entries, highest_an_rem stays where it is
	if(map->size == 0) return 0;

	struct map_entry *e = map->top;

	//move down from top unit e == NULL or ssn inside entry
	while(e != NULL && ssn_inside_entry(e, SSNrem) != 0) e = e->next;

	if(e == NULL) return 0;
	else {
		(*DSNrem) = SSNrem + (e->dsn - e->ssn);
		return 1;
	}
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: find_max_adjacent_ssn()
//	starts from bottom of table, finds max contiguous ssn
//	deletes all ssn below max_adjacent ssn
//	updates max_ssn. If table is empty, max_ssn is not updated
//++++++++++++++++++++++++++++++++++++++++++++++++
void find_max_adjacent_ssn(struct map_table *map, uint32_t *max_ssn) {
	if(map->bot == NULL) return;

	map->pnt1 = map->bot;
	while(prior_adjacent_ssn(map->pnt1)) map->pnt1 = map->pnt1->prior;
	*max_ssn = map->pnt1->ssn + map->pnt1->range -1;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: delete_below_ssn
//	deletes all entries with RE below max_ssn
//	reduces the lowest entry to max_ssn
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_below_ssn(struct map_table *map, uint32_t max_ssn) {

	//delete bottom entries: right edge of entry is smaller than max_ssn
	map->pnt1 = map->bot;
	while(map->pnt1 != NULL && sn_smaller(map->pnt1->ssn + map->pnt1->range-1, max_ssn))
		delete_entry(map);

	map->pnt1 = map->bot;

	//reset LE of bottom entry, where right edge is larger than max_ssn
	if(map->bot != NULL && sn_smaller(map->bot->ssn, max_ssn)){

		uint32_t new_range = map->bot->range - (max_ssn - map->bot->ssn);
		uint32_t offset = map->bot->dsn - map->bot->ssn;

		map->bot->ssn = max_ssn;
		map->bot->dsn = max_ssn + offset;
		map->bot->range = new_range;
	}
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//map_table: delete_below_dsn. Assumes ascending order in DSN
//	deletes all entries with RE below max_dsn
//	reduces the lowest entry to max_dsn
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_below_dsn(struct map_table *map, uint32_t max_dsn) {

	//delete bottom entries: right edge of entry is smaller than max_dsn
	map->pnt1 = map->bot;
	while(map->pnt1 != NULL && sn_smaller(map->pnt1->dsn + map->pnt1->range-1, max_dsn))
		delete_entry(map);

	map->pnt1 = map->bot;

	//reset LE of bottom entry, where right edge is larger than max_dsn
	if(map->bot != NULL && sn_smaller(map->bot->dsn, max_dsn)){

		uint32_t new_range = map->bot->range - (max_dsn - map->bot->dsn);
		uint32_t offset = map->bot->dsn - map->bot->ssn;

		map->bot->dsn = max_dsn;
		map->bot->ssn = max_dsn - offset;
		map->bot->range = new_range;
	}
}




