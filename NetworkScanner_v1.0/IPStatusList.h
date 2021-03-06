#pragma once

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

typedef uint8_t MACAddr[6];

// IP 상태 저장 구조체
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

	// index는 0부터, last item index == size - 1
	// At의 경우 스레드에 보호되지 않음.
	// 내부 아이템을 사용중 다른 곳에서 지워버린다면 문제 발생 가능.
	// 내부 아이템을 사용중이라면 직접 lock을 걸고 사용중인 아이템이 보호되도록 해야함.
	// Update Log(2015.12.02): private로 전환
	//  외부적으로 item을 얻어야할 경우 GetItem을 사용하도록 변경
	shared_ptr<IPStatusInfo> At(int index);
public:
	// Update Log: ipinfo를 직접 삽입하도록 수정
	// (2015.12.3)
	//void AddItem(uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply);
	//void InsertItem(int index, uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply);
	void AddItem(shared_ptr<IPStatusInfo> ipinfo);
	void InsertItem(int index, shared_ptr<IPStatusInfo> ipinfo);
	
	// 아이템 찾기 함수
	// ip가 내부에 있을경우 -1 반환
	int SearchItemIndex(uint32_t ip);
	int IsInItem(uint32_t ip);
	//void RemoveItem(shared_ptr<IPStatusInfo>);
	void RemoveItem(int index);

	// 스캔 재시작을 위한 초기화
	// IP, ListHead를 제외하고 전부 0으로 셋팅
	void ListInitForScan();
	// 리스트 비우기
	void ClearList();

	// 정렬
	void Sort(int, bool);

	// 리스트 아이템 얻기
	// 아이템의 내용을 고치는것에 대한 보호는 되어있지 않으므로 사용 시 주의
	shared_ptr<IPStatusInfo> GetItem(int index);

	BOOL Lock(DWORD timeout);
	void Unlock(){ ReleaseMutex(m_ListMutex); }

	int GetSize() { return m_ListHead.size(); }
public:
	CIPStatusList();
	~CIPStatusList();


	// Update 함수
	// Update Log: Update Item의 인수가 너무 많이 늘어나고 있기 때문에
	// (2015.12.3) GetItem으로 Item을 받아와서 처리하도록 변경
	//             Data 오염 주의
	//void UpdateItem(int index, uint32_t ip, uint8_t *mac, IPSTATUS ipstat, bool pingreply);
	//void UpdateItemARPInfo(int index, uint8_t *mac, IPSTATUS ipstat);
	//void UpdateItemIPStat(int index, IPSTATUS ipstat);
	//void UpdateItemPingStat(int index, IPSTATUS ipstat, bool pingreply);
};