//TP_HEAP: Heap structure to save events based on due time.
//	Adapted from binheap.c @ http://cprogramminglanguage.net/binary-heap-c-code.aspx
// Heap stores pointers of tp_event based on tp_event's member "time".
// Heap represents min-priority queue, i.e. earliest tp_event is on top.

#include "mptcpproxy_util.h"
#include "tp_heap.h"

//returns 1 if ev1 occurred earlier than ev2, otherwise 0
int earlier(struct tp_event *ev1, struct tp_event *ev2) {
	if(ev2 == NULL) return 0;
	else if(ev1 == NULL) return 1; 

	return ((1.0 * ((double)(ev2->time.tv_sec - ev1->time.tv_sec))
		 + ((double)(ev2->time.tv_usec - ev1->time.tv_usec))/1000000.0 ) > 0)? 1:0;
}

int is_due(struct tp_event *ev, struct timeval *tm) {
	//retransmit time 
	return ((1.0 * ((double)(tm->tv_sec - ev->time.tv_sec))
		 + ((double)(tm->tv_usec - ev->time.tv_usec))/1000000.0 ) > 0)? 1:0;
}



PriorityQueue Initialize(int MaxElements) {
	PriorityQueue H;
	H = malloc(sizeof ( struct HeapStruct));
	if (H == NULL) FatalError("PriorityQueue: Out of space!!!");

    	//Allocate the array plus one extra for sentinel 
	H->Elements = malloc((MaxElements + 1) * sizeof ( ElementType));
	if (H->Elements == NULL) FatalError("PriorityQueue: Out of space!!!");

	//Set all elements to NULL
	int i;
	for(i=0; i < MaxElements; i++) H->Elements[i] = NULL;

	H->Capacity = MaxElements;
	H->Size = 0;
	return H;
}

void AddCapacity(PriorityQueue H, int Nb_add) {
  	//Buffer old element arrray pointer
	ElementType *e_old = H->Elements;
	int cap_old = H->Capacity;

	//Create new element array
	H->Elements = malloc((H->Capacity + Nb_add + 1) * sizeof ( ElementType));
	if (H->Elements == NULL) FatalError("PriorityQueue:AddCapacity: Out of space!!!");	
	H->Capacity += Nb_add;

	//reinitialize to NULL
	int i;
	for(i = 0; i < H->Capacity + 1; i++) H->Elements[i] = NULL;
	H->Size = 0;

	//copy over old elements to new elements
	for(i = 0; i < cap_old + 1; i++) {
		if(e_old[i] != NULL) Insert(e_old[i], H);
	}
	//printf("AddCapacity: new capacity is now %d, size=%d\n", H->Capacity, H->Size);

}

void MakeEmpty(PriorityQueue H) {
    H->Size = 0;
}

// H->Element[ 0 ] is a sentinel
void Insert(ElementType X, PriorityQueue H) {
	if (IsFull(H)) {
		AddCapacity(H, HeapCapInc);
	}

//    for (i = ++H->Size; H->Elements[ i / 2 ] > X; i /= 2)
//       H->Elements[ i ] = H->Elements[ i / 2 ];
 
	int i;
	for (i = ++H->Size; earlier(X, H->Elements[ i / 2 ]); i /= 2){
		//printf("inserting element: earlier(X, H->Elements[ i / 2 ]=%d\n",H->Size);
		H->Elements[ i ] = H->Elements[ i / 2 ];
		//printf("inserting element i=%d\n",i);
	}
	H->Elements[ i ] = X;
}


ElementType DeleteMin(PriorityQueue H) {
    int i, Child;
    ElementType MinElement, LastElement;

    if (IsEmpty(H)) return NULL;

    MinElement = H->Elements[ 1 ];
    LastElement = H->Elements[ H->Size-- ];

    for (i = 1; i * 2 <= H->Size; i = Child) {
        //Find smaller child
        Child = i * 2;
//       if (Child != H->Size && H->Elements[ Child + 1 ] < H->Elements[ Child ]) Child++;
 	if (Child != H->Size && earlier(H->Elements[ Child + 1 ],H->Elements[ Child ])) Child++;

        //Percolate one level
        //if (LastElement > H->Elements[ Child ]) H->Elements[ i ] = H->Elements[ Child ];
        if (earlier(H->Elements[ Child ], LastElement)) H->Elements[ i ] = H->Elements[ Child ];
        else break;
    }
    H->Elements[ i ] = LastElement;
    return MinElement;
}

ElementType FindMin(PriorityQueue H) {
    if (!IsEmpty(H))
        return H->Elements[ 1 ];
    return NULL;
}

int IsEmpty(PriorityQueue H) {
    return H->Size == 0;
}

int IsFull(PriorityQueue H) {
    return H->Size == H->Capacity;
}

void Destroy(PriorityQueue H) {
    free(H->Elements);
    free(H);
}


void Error(char *str){ 
	printf("binheap: Error=%s\n", str);
	return;
}

void FatalError(char *str){
	printf("binheap: FatalError=%s\n", str);
	exit(1);
}

/*
main() {
	PriorityQueue H;
	H = Initialize(HeapCapInc);


	int i, j;

	struct tp_event ev_arr[20];

	struct timeval now;
	gettimeofday(&now, NULL);

	for(i =0; i < 20; i++){

		ev_arr[i].time.tv_sec = now.tv_sec + ((i%2) * (-1)) * (time_t) i;
		ev_arr[i].time.tv_usec = now.tv_usec + (suseconds_t) (100000 * i);
	      	Insert(&ev_arr[i], H);
		printf("Inserting event with dtime=%f\n", 
			1.0 * (ev_arr[i].time.tv_sec - now.tv_sec) +  (ev_arr[i].time.tv_usec - now.tv_usec)/1000000.0);
	}

	int size = H->Size;
	printf("Size is now=%d\n", H->Size); 
	struct tp_event *ev;
	for(i =0; i < size; i++){
//	while(FindMin(H) != NULL){
		
	 	ev =DeleteMin(H);
		if(ev==NULL) printf("event is NULL\n");
		else printf("Deleting event %d with dtime=%f\n", i,
				1.0 * (ev->time.tv_sec - now.tv_sec) +  (ev->time.tv_usec - now.tv_usec)/1000000.0);		
	}



	printf("Done...\n");
	return 0;
}

*/


