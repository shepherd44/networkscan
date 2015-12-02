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
	ClearList();
	CloseHandle(m_ListMutex);
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
	if (!Lock(INFINITE))
		return;
	PListHead lh;
	if (index > m_ListSize)
		return ;
	else
	{
		lh = &m_ListHead;
		for (int i = 0; i < index; i++)
			lh = lh->next;
	}
	
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
	if (!Lock(INFINITE))
		return;

	IPStatusInfo *temp = At(index);
	temp->IPAddress = ip;
	memcpy(temp->MACAddress, mac, 6);
	temp->IPStatus = ipstat;
	temp->PingReply = pingreply;

	Unlock();
}
void CIPStatusList::UpdateItemARPInfo(int index, uint8_t *mac, IPSTATUS ipstat)
{
	if (!Lock(INFINITE))
		return;

	IPStatusInfo *temp = At(index);
	memcpy(temp->MACAddress, mac, 6);
	temp->IPStatus = ipstat;

	Unlock();
}

void CIPStatusList::UpdateItemIPStat(int index, IPSTATUS ipstat)
{
	if (!Lock(INFINITE))
		return;

	IPStatusInfo *temp = At(index);
	temp->IPStatus = ipstat;

	Unlock();
}
void CIPStatusList::UpdateItemPingStat(int index, IPSTATUS ipstat, bool pingreply)
{
	if (!Lock(INFINITE))
		return;

	IPStatusInfo *temp = At(index);
	temp->IPStatus = ipstat;
	temp->PingReply = pingreply;
	Unlock();
}
int CIPStatusList::SearchItemIndex(uint32_t ip)
{
	int ret = 0;
	PListHead ph = m_ListHead.next;
	uint32_t itemip;
	for (; ph != &m_ListHead; ph = ph->next, ret++)
	{
		itemip = GET_LIST_ITEM(ph, IPStatusInfo, list)->IPAddress;
		if (itemip == ip)
			return -1;
		if (ntohl(itemip) > ntohl(ip))
			return ret;
	}
	return ret;
}

// IP로 검색하기
int CIPStatusList::IsInItem(uint32_t ip)
{
	int ret = 0;
	PListHead ph = m_ListHead.next;
	uint32_t itemip;
	for (; ph != &m_ListHead; ph = ph->next, ret++)
	{
		itemip = GET_LIST_ITEM(ph, IPStatusInfo, list)->IPAddress;
		if (itemip == ip)
			return ret;
	}
	return -1;
}

// 아이템 삭제
void CIPStatusList::RemoveItem(PListHead ph)
{
	if (!Lock(INFINITE))
		return;
	ListDelete(ph);
	IPStatusInfo *item = GET_LIST_ITEM(ph, IPStatusInfo, list);
	delete(item);
	m_ListSize--;
	Unlock();
}

void CIPStatusList::RemoveItem(int index)
{
	if (!Lock(INFINITE))
		return;

	PListHead ph = m_ListHead.next;
	for (int i = 0; i < index; i++)
		ph = ph->next;

	ListDelete(ph);
	IPStatusInfo *item = GET_LIST_ITEM(ph, IPStatusInfo, list);
	delete(item);
	m_ListSize--;
	
	Unlock();
}

void CIPStatusList::ClearList()
{
	if (!Lock(INFINITE))
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

IPStatusInfo* CIPStatusList::GetItem(int index)
{
	if (!Lock(INFINITE))
		return NULL;
	IPStatusInfo* itemtemp = At(index);
	Unlock();
	return itemtemp;
}

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
	{
#ifdef _DEBUG
		AfxMessageBox(L"락 실패");
#endif // _DEBUG
		return FALSE;
	}
}