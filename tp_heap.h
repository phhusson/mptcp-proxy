//TP_HEAP: Heap structure to save events based on due time.
//	Adapted from binheap.c @ http://cprogramminglanguage.net/binary-heap-c-code.aspx
// Heap stores pointers of tp_event based on tp_event's member "time".
// Heap represents min-priority queue, i.e. earliest tp_event is on top.

#include <sys/time.h>
#define HeapCapInc (50)

struct tp_event{

	struct timeval time;
	int type;
	void *data;
};

typedef struct tp_event *ElementType;

struct HeapStruct {
    int Capacity;
    int Size;
    ElementType *Elements;
};

typedef struct HeapStruct *PriorityQueue;
extern PriorityQueue PQ;

int earlier(struct tp_event *ev1, struct tp_event *ev2);

int is_due(struct tp_event *ev, struct timeval *tm);

PriorityQueue Initialize(int MaxElements);

void Destroy(PriorityQueue H);

void MakeEmpty(PriorityQueue H);

void Insert(ElementType X, PriorityQueue H);

ElementType DeleteMin(PriorityQueue H);

ElementType FindMin(PriorityQueue H);

int IsEmpty(PriorityQueue H);

int IsFull(PriorityQueue H);

void Error(char *str);

void FatalError(char *str);


