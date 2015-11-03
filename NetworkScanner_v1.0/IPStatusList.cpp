#include "stdafx.h"
#include "IPStatusList.h"


CIPStatusList::CIPStatusList()
{
	m_ListSize = 0;
	m_ListMutex = CreateMutex(NULL, FALSE, NULL);
	m_ListHead = LIST_HEAD_INIT(m_ListHead);
}


CIPStatusList::~CIPStatusList()
{
	CloseHandle(m_ListMutex);
	ClearList();
}

void CIPStatusList::AddItem(uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply)
{
	if (!Lock(INFINITE))
		return;
	int len = 0;
	IPStatusInfo *temp = new IPStatusInfo;
	memset(temp, 0, sizeof(IPStatusInfo));
	// ����Ʈ�� ����
	ListAddTail(&temp->list, &m_ListHead);
	// ����Ʈ ������ ����
	m_ListSize++;

	// �� ����
	temp->IPAddress = ip;
	memcpy(temp->MACAddress, mac, 6);
	temp->IPStatus = ipstat;
	temp->PingReply = pingreply;

	Unlock();
}

void CIPStatusList::InsertItem(int index, uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply)
{
	if (Lock(INFINITE))
		return;

	if (index >= m_ListSize)
		return ;
	PListHead lh = m_ListHead.next;
	for (int i = 0; i < index; i++)
		lh = lh->next;

	int len = 0;
	IPStatusInfo *temp = new IPStatusInfo;
	memset(temp, 0, sizeof(IPStatusInfo));
	// ����Ʈ�� ����
	ListAdd(&temp->list, &m_ListHead);
	// ����Ʈ ������ ����
	m_ListSize++;

	// �� ����
	temp->IPAddress = ip;
	memcpy(temp->MACAddress, mac, 6);
	temp->IPStatus = ipstat;
	temp->PingReply = pingreply;

	Unlock();
}

void CIPStatusList::UpdateItem(int index, uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply)
{
	if (Lock(INFINITE))
		return;

	IPStatusInfo *temp = At(index);
	temp->IPAddress = ip;
	memcpy(temp->MACAddress, mac, 6);
	temp->IPStatus = ipstat;
	temp->PingReply = pingreply;

	Unlock();
}

// IP�� �˻��ϱ�
int CIPStatusList::IsInItem(uint32_t ip)
{
	int ret = 0;
	PListHead ph = m_ListHead.next;
	uint32_t *itemip;
	for (; ph != &m_ListHead; ph = ph->next, ret++)
	{
		itemip = (uint32_t *)GET_LIST_ITEM(ph, IPStatusInfo, list);
		if (*itemip == ip)
			return ret;
	}
	return -1;
}

// ������ ����
void CIPStatusList::RemoveItem(PListHead ph)
{
	if (Lock(INFINITE))
		return;
	ListDelete(ph);
	IPStatusInfo *item = GET_LIST_ITEM(ph, IPStatusInfo, list);
	delete(item);
	m_ListSize--;
	Unlock();
}

void CIPStatusList::ClearList()
{
	if (Lock(INFINITE))
		return;
	PListHead ph = m_ListHead.next;
	for (; ph != &m_ListHead; ph = m_ListHead.next)
	{
		ListDelete(ph);
		IPStatusInfo *item = GET_LIST_ITEM(ph, IPStatusInfo, list);
		delete(item);
		m_ListSize--;
	}
	Unlock();
}

// index�� 0����, last item index == size - 1
// At�� ��� �����忡 ��ȣ���� ����. 
// ���� �������� ������̶�� ���� lock�� �ɰ� ������� �������� ��ȣ�ǵ��� �ؾ���.
IPStatusInfo* CIPStatusList::At(int index)
{
	if (index >= m_ListSize)
		return NULL;
	PListHead hp = m_ListHead.next;
	for (int i = 0; i < index; i++)
		hp = hp->next;
	return GET_LIST_ITEM(hp, IPStatusInfo, list);
}

BOOL CIPStatusList::Lock(DWORD timeout)
{
	if (WaitForSingleObject(m_ListMutex, timeout) == WAIT_OBJECT_0)
		return TRUE;
	else
		return FALSE;
}