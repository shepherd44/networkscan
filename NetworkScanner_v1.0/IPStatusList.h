#pragma once

#include "linkedlist.h"
#include <stdint.h>

// IP ���� üũ
enum IPSTATUS
{
	NOTUSING = 0,		// ��������� ����
	USING,			// �����
	USING_GATEWAY,	// ����Ʈ����
	IPDUPLICATION,	// IP �ߺ� ���
	ONLYPING,	// �ٸ� ��Ʈ��ũ - (B Class �˻� ���� �� ���, ���� C Class�� ����)

	IPSTATUSEND			// ������ ��
};

// IP ���� ���� ����ü
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
	// ip�� ���ο� ������� -1 ��ȯ
	int SearchItemIndex(uint32_t ip);
	int IsInItem(uint32_t ip);
	void RemoveItem(PListHead ph);
	void RemoveItem(int index);
	void ClearList();

	// index�� 0����, last item index == size - 1
	// At�� ��� �����忡 ��ȣ���� ����.
	// ���� �������� ����� �ٸ� ������ ���������ٸ� ���� �߻� ����.
	// ���� �������� ������̶�� ���� lock�� �ɰ� ������� �������� ��ȣ�ǵ��� �ؾ���.
	IPStatusInfo* At(int index);

	BOOL Lock(DWORD timeout);
	void Unlock(){ ReleaseMutex(m_ListMutex); }

	int GetSize() { return m_ListSize; }
public:
	CIPStatusList();
	~CIPStatusList();
};