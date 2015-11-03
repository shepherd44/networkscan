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

// ����Ʈ ��� �ʱ�ȭ
void InitListHead(PListHead list);

// ������ �߰�
void __ListAdd(PListHead newnode, PListHead prevnode, PListHead nextnode);
void ListAdd(PListHead newnode, PListHead head);
void ListAddTail(PListHead newnode, PListHead head);

// ����Ʈ ������ ����, �ش� ��带 ���� �������� ���� ���������
void __ListDelete(PListHead prevnode, PListHead nextnode);
void ListDelete(PListHead item);

// ��� �ϳ��� �ٸ� ���� �ű��
//void ListMove(PListHead newnode, PListHead head);
//void ListMoveTail(PListHead newnode, PListHead head);

// ����Ʈ�� ������� Ȯ��
bool ListIsEmpty(PListHead head);
// ����Ʈ ������ ���
int ListSize(PListHead head);

#endif