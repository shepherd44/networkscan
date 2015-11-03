#pragma once

#include <vector>

#include "ARPSocket.h"

// IP ���� üũ
enum IPSTATUS
{
	NOTUSING = 0,		// ��������� ����
	USING = 1,			// �����
	USING_GATEWAY = 2,	// ����Ʈ����
	UNKNOWN = 3,		// Ȯ�� �ȵ�
	IPDUPLICATION = 4,	// IP �ߺ� ���
	OTHERNETWORK = 5,	// �ٸ� ��Ʈ��ũ - (B Class �˻� ���� �� ���, ���� C Class�� ����)

	IPSTATUSEND			// ������ ��
};

// IP ���� ���� ����ü
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

