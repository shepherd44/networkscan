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

typedef uint8_t MACAddr[6];

// IP ���� ���� ����ü
typedef struct IPStatusInfo
{
	//Target IP
	uint32_t	IPAddress;		// IP Address
	uint8_t		MACAddress[6];	// MAC
	IPSTATUS	IPStatus;
	
	// ARP Info
	bool		DoARPPingSend;
	struct timeval LastARPSendTime;
	struct timeval LastARPRecvTime;
	
	// Ping Info
	bool		DoIPPingSend;
	struct timeval LastPingSendTime;
	struct timeval LastPingRecvTime;
	bool		PingReply;

	// Duplicate MAC List
	MACAddr *DuplicationMAC;
	int DuplicationMACCount;
	
	ListHead	list;	// list head
}IPStatusInfo;

class CIPStatusList
{
	ListHead m_ListHead;
	int m_ListSize;
	HANDLE m_ListMutex;

	// index�� 0����, last item index == size - 1
	// At�� ��� �����忡 ��ȣ���� ����.
	// ���� �������� ����� �ٸ� ������ ���������ٸ� ���� �߻� ����.
	// ���� �������� ������̶�� ���� lock�� �ɰ� ������� �������� ��ȣ�ǵ��� �ؾ���.
	// Update Log(2015.12.02): private�� ��ȯ
	//  �ܺ������� item�� ������ ��� GetItem�� ����ϵ��� ����
	IPStatusInfo* At(int index);
public:
	// Update Log: ipinfo�� ���� �����ϵ��� ����
	// (2015.12.3)
	//void AddItem(uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply);
	//void InsertItem(int index, uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply);
	void AddItem(IPStatusInfo *ipinfo);
	void InsertItem(int index, IPStatusInfo *ipinfo);
	
	// ip�� ���ο� ������� -1 ��ȯ
	int SearchItemIndex(uint32_t ip);
	int IsInItem(uint32_t ip);
	void RemoveItem(PListHead ph);
	void RemoveItem(int index);

	// ��ĵ ������� ���� �ʱ�ȭ
	// IP, ListHead�� �����ϰ� ���� 0���� ����
	void ListInitForScan();
	// ����Ʈ ����
	void ClearList();

	// ����Ʈ ������ ���
	// �������� ������ ��ġ�°Ϳ� ���� ��ȣ�� �Ǿ����� �����Ƿ� ��� �� ����
	IPStatusInfo* GetItem(int index);

	BOOL Lock(DWORD timeout);
	void Unlock(){ ReleaseMutex(m_ListMutex); }

	int GetSize() { return m_ListSize; }
public:
	CIPStatusList();
	~CIPStatusList();


	// Update �Լ�
	// Update Log: Update Item�� �μ��� �ʹ� ���� �þ�� �ֱ� ������
	// (2015.12.3) GetItem���� Item�� �޾ƿͼ� ó���ϵ��� ����
	//             Data ���� ����
	//void UpdateItem(int index, uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply);
	//void UpdateItemARPInfo(int index, uint8_t *mac, IPSTATUS ipstat);
	//void UpdateItemIPStat(int index, IPSTATUS ipstat);
	//void UpdateItemPingStat(int index, IPSTATUS ipstat, bool pingreply);
};