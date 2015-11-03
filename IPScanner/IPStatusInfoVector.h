#pragma once

#include <vector>

#include "ARPSocket.h"

// IP 상태 체크
enum IPSTATUS
{
	NOTUSING = 0,		// 사용중이지 않음
	USING = 1,			// 사용중
	USING_GATEWAY = 2,	// 게이트웨이
	UNKNOWN = 3,		// 확인 안됨
	IPDUPLICATION = 4,	// IP 중복 사용
	OTHERNETWORK = 5,	// 다른 네트워크 - (B Class 검색 지원 시 사용, 현재 C Class만 지원)

	IPSTATUSEND			// 열거형 끝
};

// IP 상태 저장 구조체
typedef struct IPStatusInfo
{
	unsigned long m_IPAddress;
	IPSTATUS m_IPStatus;
	unsigned char m_MACAddress[6];
}IPStatusInfo;

using namespace std;


class CIPStatusInfoVector
{
private:
	vector<IPStatusInfo> m_HeadIPStatusInfo;

public:
	void VectorClear();
	void VectorResize(int size);
	void VectorSetItem(int index, u_long ip, IPSTATUS ipstat, u_char *mac);
	void VectorPushBackItem(u_long ip, IPSTATUS ipstat, u_char *mac);
	void VectorInsertItem(int index, u_long ip, IPSTATUS ipstat, u_char *mac);
	int GetSize();

public:
	IPStatusInfo& operator[] (int index) { return m_HeadIPStatusInfo[index]; }

public:
	CIPStatusInfoVector();
	~CIPStatusInfoVector();
};

