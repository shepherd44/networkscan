#include "linkedlist.h"

// ����Ʈ ��� �ʱ�ȭ
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

// ����Ʈ ����
void __ListDelete(PListHead prevnode, PListHead nextnode)
{
	prevnode->next = nextnode;
	nextnode->prev = prevnode;
}

void ListDelete(PListHead item)
{
	__ListDelete(item->prev, item->next);
}

// ��� �ϳ��� �ٸ� ���� �ű��
//void ListMove(PListHead newnode, PListHead head);
//void ListMoveTail(PListHead newnode, PListHead head);

// ����Ʈ�� ������� Ȯ��
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