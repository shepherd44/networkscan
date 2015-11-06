#pragma once

#include "linkedlist.h"
#include <stdint.h>

// IP 상태 체크
enum IPSTATUS
{
	NOTUSING = 0,		// 사용중이지 않음
	USING,			// 사용중
	USING_GATEWAY,	// 게이트웨이
	IPDUPLICATION,	// IP 중복 사용
	ONLYPING,	// 다른 네트워크 - (B Class 검색 지원 시 사용, 현재 C Class만 지원)

	IPSTATUSEND			// 열거형 끝
};

// IP 상태 저장 구조체
typedef struct IPStatusInfo
{
	uint32_t IPAddress;
	uint8_t MACAddress[6];
	IPSTATUS IPStatus;
	bool	PingReply;
	ListHead list;
}IPStatusInfo;

class CIPStatusList
{
	ListHead m_ListHead;
	int m_ListSize;
	HANDLE m_ListMutex;

public:
	void AddItem(uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply);
	void InsertItem(int index, uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply);
	void UpdateItem(int index, uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply);
	void UpdateItemARPInfo(int index, uint8_t *mac, IPSTATUS ipstat);
	void UpdateItemIPStat(int index, IPSTATUS ipstat);
	void UpdateItemPingStat(int index, IPSTATUS ipstat, bool pingreply);
	// ip가 내부에 있을경우 -1 반환
	int SearchItemIndex(uint32_t ip);
	int IsInItem(uint32_t ip);
	void RemoveItem(PListHead ph);
	void RemoveItem(int index);
	void ClearList();

	// index는 0부터, last item index == size - 1
	// At의 경우 스레드에 보호되지 않음.
	// 내부 아이템을 사용중 다른 곳에서 지워버린다면 문제 발생 가능.
	// 내부 아이템을 사용중이라면 직접 lock을 걸고 사용중인 아이템이 보호되도록 해야함.
	IPStatusInfo* At(int index);

	BOOL Lock(DWORD timeout);
	void Unlock(){ ReleaseMutex(m_ListMutex); }

	int GetSize() { return m_ListSize; }
public:
	CIPStatusList();
	~CIPStatusList();
};