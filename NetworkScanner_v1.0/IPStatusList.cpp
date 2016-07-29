#include "stdafx.h"
#include "IPStatusList.h"


CIPStatusList::CIPStatusList()
{
	m_ListMutex = CreateMutex(NULL, FALSE, NULL);
}


CIPStatusList::~CIPStatusList()
{
	ClearList();
	CloseHandle(m_ListMutex);
}

void CIPStatusList::AddItem(shared_ptr<IPStatusInfo> ipinfo)
{
	if (!Lock(INFINITE))
		return;
	
	// 리스트에 삽입
	m_ListHead.push_back(ipinfo);
	
	Unlock();
}

void CIPStatusList::InsertItem(int index, shared_ptr<IPStatusInfo> ipinfo)
{
	if (!Lock(INFINITE))
		return;
	list< shared_ptr<IPStatusInfo> >::iterator bi = m_ListHead.begin();

	if (index > (int)m_ListHead.size())
		return;
	else
	{
		for (int i = 0; i < index; i++)
			bi++;
	}

	// 리스트에 삽입
	m_ListHead.insert(bi, ipinfo);
	
	Unlock();
}

int CIPStatusList::SearchItemIndex(uint32_t ip)
{
	int ret = 0;

	list< shared_ptr<IPStatusInfo> >::iterator bi = m_ListHead.begin();
	list< shared_ptr<IPStatusInfo> >::iterator ei = m_ListHead.end();
	shared_ptr<IPStatusInfo> item;
	uint32_t itemip;
	for (; bi != ei; bi++, ret++)
	{
		item = *bi;
		itemip = item->IPAddress;
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
	list< shared_ptr<IPStatusInfo> >::iterator bi = m_ListHead.begin();
	list< shared_ptr<IPStatusInfo> >::iterator ei = m_ListHead.end();
	shared_ptr<IPStatusInfo> item;
	uint32_t itemip;

	for (; bi != ei; bi++, ret++)
	{
		item = *bi;
		itemip = item->IPAddress;
		if (itemip == ip)
			return ret;
	}
	return -1;
}

void CIPStatusList::RemoveItem(int index)
{
	if (!Lock(INFINITE))
		return;

	if (index >= (int)m_ListHead.size())
		return;

	list< shared_ptr<IPStatusInfo> >::iterator bi = m_ListHead.begin();

	for (int i = 0; i < index; i++)
		bi++;
		
	m_ListHead.erase(bi);
		
	Unlock();
}

void CIPStatusList::ClearList()
{
	if (!Lock(INFINITE))
		return;
	m_ListHead.clear();
	Unlock();
}

void CIPStatusList::Sort(int col, bool dir)
{
	switch (col)
	{
	case 1:	// IP Address 기준 정렬
		if (dir)
			m_ListHead.sort(IPStatusInfoSort<1,true>());
		else
			m_ListHead.sort(IPStatusInfoSort<1,false>());
		break;
	case 5:	// IP Status 기준 정렬
		if (dir)
			m_ListHead.sort(IPStatusInfoSort<5, true>());
		else
			m_ListHead.sort(IPStatusInfoSort<5, false>());
		break;
	default:
		break;
	}
	
};

void CIPStatusList::ListInitForScan()
{
	if (!Lock(INFINITE))
		return;
	
	list< shared_ptr<IPStatusInfo> >::iterator bi = m_ListHead.begin();
	list< shared_ptr<IPStatusInfo> >::iterator ei = m_ListHead.end();
	shared_ptr<IPStatusInfo> item;
	
	for (; bi != ei; bi++)
	{
		item = *bi;
		// 해당 item 초기화
		// 초기화 제외 목록: ipaddredd, dopingsend, doarpsend, list
		memset(item->MACAddress, 0, sizeof(timeval));
		item->IPStatus = IPSTATUS::NOTUSING;
		memset(&item->LastARPRecvTime, 0, sizeof(timeval));
		memset(&item->LastARPSendTime, 0, sizeof(timeval));
		memset(&item->LastPingRecvTime, 0, sizeof(timeval));
		memset(&item->LastPingSendTime, 0, sizeof(timeval));

		if (item->DuplicationMAC != NULL)
			delete[]item->DuplicationMAC;
		item->DuplicationMACCount = 0;
	}

	Unlock();
}

shared_ptr<IPStatusInfo> CIPStatusList::GetItem(int index)
{
	if (!Lock(INFINITE))
		return NULL;
	shared_ptr<IPStatusInfo> itemtemp = At(index);
	Unlock();
	return itemtemp;
}

shared_ptr<IPStatusInfo> CIPStatusList::At(int index)
{
	if (index >= (int)m_ListHead.size())
		return NULL;

	list< shared_ptr<IPStatusInfo> >::iterator bi = m_ListHead.begin();
	list< shared_ptr<IPStatusInfo> >::iterator ei = m_ListHead.end();
	shared_ptr<IPStatusInfo> item;

	for (int i = 0; i < index; i++)
		bi++;
	item = *bi;

	return item;
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

// Update Log: 이제 사용하지 않게되어 주석 처리해둠
// (2015.12.3)
//void CIPStatusList::AddItem(uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply)
//{
//	if (!Lock(INFINITE))
//		return;
//	int len = 0;
//	IPStatusInfo *temp = new IPStatusInfo;
//	memset(temp, 0, sizeof(IPStatusInfo));
//	// 리스트에 삽입
//	ListAddTail(&temp->list, &m_ListHead);
//	// 리스트 사이즈 증가
//	m_ListSize++;
//
//	// 값 셋팅
//	temp->IPAddress = ip;
//	memcpy(temp->MACAddress, mac, 6);
//	temp->IPStatus = ipstat;
//	temp->PingReply = pingreply;
//
//	Unlock();
//}
//void CIPStatusList::InsertItem(int index, uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply)
//{
//	if (!Lock(INFINITE))
//		return;
//	PListHead lh;
//	if (index > m_ListSize)
//		return ;
//	else
//	{
//		lh = &m_ListHead;
//		for (int i = 0; i < index; i++)
//			lh = lh->next;
//	}
//	
//	IPStatusInfo *temp = new IPStatusInfo;
//	memset(temp, 0, sizeof(IPStatusInfo));
//	// 리스트에 삽입
//	ListAdd(&temp->list, lh);
//	// 리스트 사이즈 증가
//	m_ListSize++;
//
//	// 값 셋팅
//	temp->IPAddress = ip;
//	memcpy(temp->MACAddress, mac, MACADDRESS_LENGTH);
//	temp->IPStatus = ipstat;
//	temp->PingReply = pingreply;
//
//	Unlock();
//}
//void CIPStatusList::UpdateItem(int index, uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply)
//{
//	if (!Lock(INFINITE))
//		return;
//
//	IPStatusInfo *temp = At(index);
//	temp->IPAddress = ip;
//	memcpy(temp->MACAddress, mac, 6);
//	temp->IPStatus = ipstat;
//	temp->PingReply = pingreply;
//
//	Unlock();
//}
//void CIPStatusList::UpdateItemARPInfo(int index, uint8_t *mac, IPSTATUS ipstat)
//{
//	if (!Lock(INFINITE))
//		return;
//
//	IPStatusInfo *temp = At(index);
//	memcpy(temp->MACAddress, mac, 6);
//	temp->IPStatus = ipstat;
//
//	Unlock();
//}
//void CIPStatusList::UpdateItemIPStat(int index, IPSTATUS ipstat)
//{
//	if (!Lock(INFINITE))
//		return;
//
//	IPStatusInfo *temp = At(index);
//	temp->IPStatus = ipstat;
//
//	Unlock();
//}
//void CIPStatusList::UpdateItemPingStat(int index, IPSTATUS ipstat, bool pingreply)
//{
//	if (!Lock(INFINITE))
//		return;
//
//	IPStatusInfo *temp = At(index);
//	temp->IPStatus = ipstat;
//	temp->PingReply = pingreply;
//	Unlock();
//}