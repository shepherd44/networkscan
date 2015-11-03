#include "linkedlist.h"

// 리스트 헤드 초기화
void InitListHead(PListHead list)
{
	list->next = list;
	list->prev = list;
}

//
void __ListAdd(PListHead newnode, PListHead prevnode, PListHead nextnode)
{
	nextnode->prev = newnode;
	newnode->next = nextnode;
	newnode->prev = prevnode;
	prevnode->next = newnode;
}
void ListAdd(PListHead newnode, PListHead head)
{
	__ListAdd(newnode, head, head->next);
}
void ListAddTail(PListHead newnode, PListHead head)
{
	__ListAdd(newnode, head->prev, head);
}

// 리스트 삭제
void __ListDelete(PListHead prevnode, PListHead nextnode)
{
	prevnode->next = nextnode;
	nextnode->prev = prevnode;
}

void ListDelete(PListHead item)
{
	__ListDelete(item->prev, item->next);
}

// 노드 하나를 다른 노드로 옮기기
//void ListMove(PListHead newnode, PListHead head);
//void ListMoveTail(PListHead newnode, PListHead head);

// 리스트가 비었는지 확인
bool ListIsEmpty(PListHead head)
{
	if (head->next == head)
		return true;
	else
		return false;
}

int ListSize(PListHead head)
{
	PListHead ph = head;
	int i = 0;
	for (; ph; ph = ph->next)
		i++;
	return i;
}