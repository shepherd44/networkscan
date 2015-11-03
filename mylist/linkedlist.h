// linked list

#ifndef _LINKEDLIST_H__
#define _LINKEDLIST_H__

typedef struct ListHead
{
	ListHead *next, *prev;
}ListHead, *PListHead;

#define LIST_HEAD_INIT(name)	{&(name), &(name)}
#define LIST_HEAD(name)			ListHead name = LIST_HEAD_INIT(name)

#ifdef offsetof
#define GET_LIST_ITEM(listptr, type, listname)	((type*)(((size_t)(listptr)) - (offsetof(type, listname))))
//#define CURRENT_ITEM(listptr, type, listname)	((type*)(((size_t)(listptr)) - (offsetof(type, listname))))
#else
#define offsetof(type, member)		((size_t) &((type *)0)->member)
#define GET_LIST_ITEM(listptr, type, listname)		((type*)(((size_t)(listptr)) - offsetof(type, listname)))
#endif

#define list_for_each(pos, head)		for (pos = (head)->next; pos != (head); pos = pos->next)

// 리스트 헤드 초기화
void InitListHead(PListHead list);

// 아이템 추가
void __ListAdd(PListHead newnode, PListHead prevnode, PListHead nextnode);
void ListAdd(PListHead newnode, PListHead head);
void ListAddTail(PListHead newnode, PListHead head);

// 리스트 아이템 삭제, 해당 노드를 가진 아이템은 직접 지워줘야함
void __ListDelete(PListHead prevnode, PListHead nextnode);
void ListDelete(PListHead item);

// 노드 하나를 다른 노드로 옮기기
//void ListMove(PListHead newnode, PListHead head);
//void ListMoveTail(PListHead newnode, PListHead head);

// 리스트가 비었는지 확인
bool ListIsEmpty(PListHead head);
// 리스트 사이즈 얻기
int ListSize(PListHead head);

#endif