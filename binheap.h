//http://cprogramminglanguage.net/binary-heap-c-code.aspx

typedef int ElementType;

#ifndef _BinHeap_H
#define _BinHeap_H

struct HeapStruct;
typedef struct HeapStruct *PriorityQueue;

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
#endif

