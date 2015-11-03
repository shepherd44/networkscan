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
	// 리스트에 삽입
	ListAddTail(&temp->list, &m_ListHead);
	// 리스트 사이즈 증가
	m_ListSize++;

	// 값 셋팅
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

	IPStatusInfo *temp = new IPStatusInfo;
	memset(temp, 0, sizeof(IPStatusInfo));
	// 리스트에 삽입
	ListAdd(&temp->list, lh);
	// 리스트 사이즈 증가
	m_ListSize++;

	// 값 셋팅
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

void CIPStatusList::UpdateItemIPStat(int index, IPSTATUS ipstat)
{
	if (Lock(INFINITE))
		return;

	IPStatusInfo *temp = At(index);
	temp->IPStatus = ipstat;

	Unlock();
}
void CIPStatusList::UpdateItemPingStat(int index, bool pingreply)
{
	if (Lock(INFINITE))
		return;

	IPStatusInfo *temp = At(index);
	temp->PingReply = pingreply;
	Unlock();
}

// IP로 검색하기
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

// 아이템 삭제
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

// index는 0부터, last item index == size - 1
// At의 경우 스레드에 보호되지 않음. 
// 내부 아이템을 사용중이라면 직접 lock을 걸고 사용중인 아이템이 보호되도록 해야함.
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