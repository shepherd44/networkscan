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

// 저장 아이템 비우기
void CIPStatusInfoVector::VectorClear()
{
	m_HeadIPStatusInfo.clear();
}

// 벡터 비우고 사이즈 조절
void CIPStatusInfoVector::VectorResize(int size)
{
	VectorClear();
	m_HeadIPStatusInfo.resize(size);
}

// n번째 아이템 수정
void CIPStatusInfoVector::VectorSetItem(int index, u_long ip, IPSTATUS ipstat, u_char *mac)
{
	IPStatusInfo ipstatinfo;
	if (static_cast<u_int>(index) > m_HeadIPStatusInfo.size())
		throw std::exception("결과 저장 벡터 사이즈보다 큽니다.");

	ipstatinfo.m_IPAddress = ip;
	ipstatinfo.m_IPStatus = ipstat;
	memcpy(ipstatinfo.m_MACAddress, mac, MACADDRESSLENGTH);
	memcpy(&m_HeadIPStatusInfo[index], &ipstatinfo, sizeof(IPStatusInfo));
}

// 제일 뒤에 아이템 삽입
void CIPStatusInfoVector::VectorPushBackItem(u_long ip, IPSTATUS ipstat, u_char *mac)
{
	IPStatusInfo ipstatinfo;
	ipstatinfo.m_IPAddress = ip;
	ipstatinfo.m_IPStatus = ipstat;
	memcpy(ipstatinfo.m_MACAddress, mac, MACADDRESSLENGTH);
	m_HeadIPStatusInfo.push_back(ipstatinfo);
}

// n번째에 아이템 삽입
void CIPStatusInfoVector::VectorInsertItem(int index, u_long ip, IPSTATUS ipstat, u_char *mac)
{
	IPStatusInfo ipstatinfo;
	if (static_cast<u_int>(index) > m_HeadIPStatusInfo.size())
		throw std::exception("결과 저장 벡터 사이즈보다 큽니다.");

	ipstatinfo.m_IPAddress = ip;
	ipstatinfo.m_IPStatus = ipstat;
	memcpy(ipstatinfo.m_MACAddress, mac, MACADDRESSLENGTH);

	std::vector<IPStatusInfo>::iterator vi = m_HeadIPStatusInfo.begin();
	for (int i = 0; i < index; i++, vi++);
	m_HeadIPStatusInfo.insert(vi, ipstatinfo);
}

// 벡터 사이즈 반환
int CIPStatusInfoVector::GetSize()
{
	return m_HeadIPStatusInfo.size();
}