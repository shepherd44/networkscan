#include "stdafx.h"
#include "IPStatusInfoVector.h"

CIPStatusInfoVector::CIPStatusInfoVector()
{
	VectorClear();
}

CIPStatusInfoVector::~CIPStatusInfoVector()
{
	VectorClear();
}

// ���� ������ ����
void CIPStatusInfoVector::VectorClear()
{
	m_HeadIPStatusInfo.clear();
}

// ���� ���� ������ ����
void CIPStatusInfoVector::VectorResize(int size)
{
	VectorClear();
	m_HeadIPStatusInfo.resize(size);
}

// n��° ������ ����
void CIPStatusInfoVector::VectorSetItem(int index, u_long ip, IPSTATUS ipstat, u_char *mac)
{
	IPStatusInfo ipstatinfo;
	if (static_cast<u_int>(index) > m_HeadIPStatusInfo.size())
		throw std::exception("��� ���� ���� ������� Ů�ϴ�.");

	ipstatinfo.m_IPAddress = ip;
	ipstatinfo.m_IPStatus = ipstat;
	memcpy(ipstatinfo.m_MACAddress, mac, MACADDRESSLENGTH);
	memcpy(&m_HeadIPStatusInfo[index], &ipstatinfo, sizeof(IPStatusInfo));
}

// ���� �ڿ� ������ ����
void CIPStatusInfoVector::VectorPushBackItem(u_long ip, IPSTATUS ipstat, u_char *mac)
{
	IPStatusInfo ipstatinfo;
	ipstatinfo.m_IPAddress = ip;
	ipstatinfo.m_IPStatus = ipstat;
	memcpy(ipstatinfo.m_MACAddress, mac, MACADDRESSLENGTH);
	m_HeadIPStatusInfo.push_back(ipstatinfo);
}

// n��°�� ������ ����
void CIPStatusInfoVector::VectorInsertItem(int index, u_long ip, IPSTATUS ipstat, u_char *mac)
{
	IPStatusInfo ipstatinfo;
	if (static_cast<u_int>(index) > m_HeadIPStatusInfo.size())
		throw std::exception("��� ���� ���� ������� Ů�ϴ�.");

	ipstatinfo.m_IPAddress = ip;
	ipstatinfo.m_IPStatus = ipstat;
	memcpy(ipstatinfo.m_MACAddress, mac, MACADDRESSLENGTH);

	std::vector<IPStatusInfo>::iterator vi = m_HeadIPStatusInfo.begin();
	for (int i = 0; i < index; i++, vi++);
	m_HeadIPStatusInfo.insert(vi, ipstatinfo);
}

// ���� ������ ��ȯ
int CIPStatusInfoVector::GetSize()
{
	return m_HeadIPStatusInfo.size();
}