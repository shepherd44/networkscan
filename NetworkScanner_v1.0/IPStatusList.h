#pragma once

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
}IPStatusInfo;

template<int col = 1, bool dir = false>
class IPStatusInfoSort
{
public:
	bool operator() (shared_ptr<IPStatusInfo>& left, shared_ptr<IPStatusInfo>& right) const
	{
		switch (col)
		{
		case 1:
			if (left->IPAddress < right->IPAddress)
				if (dir)
					return true;
				else
					return false;
			else
				if (dir)
					return false;
				else
					return true;
			break;
		case 5:
			if (left->IPStatus < right->IPStatus)
				if (dir)
					return true;
				else
					return false;
			else
				if (dir)
					return false;
				else
					return true;
			break;
		default:
			break;
		}
		
	}

	void SetSortColumn(int col) { m_SortCol = col; }
	void SetSortDirection(bool Dir) { m_SortDirection = Dir; }
private:
	int m_SortCol;
	bool m_SortDirection;
};

template<bool tb>
bool SortFuncIPAddr(shared_ptr<IPStatusInfo>& left, shared_ptr<IPStatusInfo>& right)
{
	u_long leftIP = left->IPAddress;
	u_long rightIP = right->IPAddress;
	if (leftIP < rightIP)
		if (tb)
			return true;
		else
			return false;
	else
		if (tb)
			return false;
		else
			return true;
}


class CIPStatusList
{
	list< shared_ptr<IPStatusInfo> > m_ListHead;
	HANDLE m_ListMutex;

	// index�� 0����, last item index == size - 1
	// At�� ��� �����忡 ��ȣ���� ����.
	// ���� �������� ����� �ٸ� ������ ���������ٸ� ���� �߻� ����.
	// ���� �������� ������̶�� ���� lock�� �ɰ� ������� �������� ��ȣ�ǵ��� �ؾ���.
	// Update Log(2015.12.02): private�� ��ȯ
	//  �ܺ������� item�� ������ ��� GetItem�� ����ϵ��� ����
	shared_ptr<IPStatusInfo> At(int index);
public:
	// Update Log: ipinfo�� ���� �����ϵ��� ����
	// (2015.12.3)
	//void AddItem(uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply);
	//void InsertItem(int index, uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply);
	void AddItem(shared_ptr<IPStatusInfo> ipinfo);
	void InsertItem(int index, shared_ptr<IPStatusInfo> ipinfo);
	
	// ������ ã�� �Լ�
	// ip�� ���ο� ������� -1 ��ȯ
	int SearchItemIndex(uint32_t ip);
	int IsInItem(uint32_t ip);
	//void RemoveItem(shared_ptr<IPStatusInfo>);
	void RemoveItem(int index);

	// ��ĵ ������� ���� �ʱ�ȭ
	// IP, ListHead�� �����ϰ� ���� 0���� ����
	void ListInitForScan();
	// ����Ʈ ����
	void ClearList();

	// ����
	void Sort(int, bool);

	// ����Ʈ ������ ���
	// �������� ������ ��ġ�°Ϳ� ���� ��ȣ�� �Ǿ����� �����Ƿ� ��� �� ����
	shared_ptr<IPStatusInfo> GetItem(int index);

	BOOL Lock(DWORD timeout);
	void Unlock(){ ReleaseMutex(m_ListMutex); }

	int GetSize() { return m_ListHead.size(); }
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