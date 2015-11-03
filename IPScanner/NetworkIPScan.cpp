#include "stdafx.h"
#include "NetworkIPScan.h"


CNetworkIPScan::CNetworkIPScan()
{
	InitializeAll();
}


CNetworkIPScan::~CNetworkIPScan()
{
}


// 초기화 함수
void CNetworkIPScan::InitializeAll()
{
	HANDLE m_hCaptureThread = NULL;
	AdapterInfoInit();
}

// 아답터 정보 초기화
// 초기화 대상: NIC IP, NIC MAC, Gateway IP
void CNetworkIPScan::AdapterInfoInit()
{
	DWORD size = sizeof(PIP_ADAPTER_INFO);
	int ss = sizeof(IP_ADAPTER_INFO);
	u_long ipaddr;
	PIP_ADAPTER_INFO Info;
	ZeroMemory(&Info, size);

	// 네트워크 인터페이스 정보 가져오기
	int result = GetAdaptersInfo(Info, &size);
	if (result == ERROR_BUFFER_OVERFLOW)
	{
		Info = (PIP_ADAPTER_INFO)malloc(size);
		GetAdaptersInfo(Info, &size);
	}

	// NIC MAC 주소
	memcpy(m_NICMACAddress, Info->Address, MACADDRESSLENGTH);
	// NIC IP 주소
	ipaddr = inet_addr(Info->IpAddressList.IpAddress.String);
	memcpy(m_NICIPAddress, &ipaddr, IPV4ADDRESSLENGTH);
	// NIC Netmask
	ipaddr = inet_addr(Info->IpAddressList.IpMask.String);
	memcpy(m_NICNetmask, &ipaddr, IPV4ADDRESSLENGTH);
	// Gateway IP 주소
	ipaddr = inet_addr(Info->GatewayList.IpAddress.String);
	memcpy(m_GatewayIPAddress, &ipaddr, IPV4ADDRESSLENGTH);

	// 아답터 정보 해제
	free(Info);
}

// 스캔 시작
void CNetworkIPScan::Scan(u_long hbeginip, u_long hendip)
{
	// 입력된 IP 주소 처리
	u_long size = 0;
	m_BeginIP = htonl(hbeginip);
	m_EndIP = htonl(hendip);

	// 저장 벡터 초기화
	size = hendip - hbeginip + 1;
	m_vhIPStatusInfo.VectorResize(size);

	// 스캔 시작 ( ARP Capture )
	StartCapture();
	// ARP 패킷 송신
	SendARP(m_BeginIP, m_EndIP);
	// 패킷 캡쳐 기다리기
	Sleep(1000);
	// 캡쳐 끝내기
	EndCapture();
	// 분석
	Analyze();
}

// 지정된 범위의 IP에 ARP 요청
int CNetworkIPScan::SendARP(u_long beginip, u_long end_ip)
{
	CARPSocket arpsock;
	u_long ip = beginip;
	u_long rip = ntohl(ip);

	int i = 0;
	for (; rip <= ntohl(end_ip); rip++, i++)
		arpsock.SendPacket(htonl(rip));
	return i;
}

// 쓰레드용 캡처 시작 함수 
DWORD WINAPI CNetworkIPScan::ARPCaptueThreadFunc(LPVOID lpParam)
{
	CARPSocket *arpsock = (CARPSocket *)lpParam;
	arpsock->StartCapture();
	return 0;
}

// 캡쳐 시작, 쓰레드 사용.
// EndCapture()로 종료
void CNetworkIPScan::StartCapture()
{
	DWORD dwCaptureThreadId;
	m_hCaptureThread = CreateThread(NULL,
		0,
		CNetworkIPScan::ARPCaptueThreadFunc,
		&m_ARPCaptureSock,
		0,
		&dwCaptureThreadId);
	if (m_hCaptureThread == NULL)
		throw std::exception("스레드 시작 실패");
}

// 캡처 종료
void CNetworkIPScan::EndCapture()
{
	// 종료 신호 보내기
	m_ARPCaptureSock.EndCapture();
	// 쓰레드 핸들 닫기
	CloseHandle(m_hCaptureThread);
}

// 캡처 결과 분석
void CNetworkIPScan::Analyze()
{
	u_long nbip = m_BeginIP, neip = m_EndIP;	// 시작, 끝 ip (네트워크 정렬)
	u_long hbip = htonl(nbip), heip = htonl(neip);	// 시작, 끝 ip (호스트 정렬)
	
	// 분석
	std::list<ARPPacket>::iterator bli = m_ARPCaptureSock.GetCaptureListBegin();	// 캡쳐 결과 리스트 시작
	std::list<ARPPacket>::iterator eli = m_ARPCaptureSock.GetCaptureListEnd();		// 캡쳐 결과 리스트 끝

	u_long nmyip, hmyip;
	int index;
	int addition = 0;
	u_long nsip, hsip;

	memcpy(&nmyip, m_NICIPAddress, IPV4ADDRESSLENGTH);
	hmyip = ntohl(nmyip);
	// 내 IP 상태 추가
	if (hmyip >= hbip && hmyip <= heip)
	{
		index = hmyip - hbip;
		m_vhIPStatusInfo.VectorSetItem(index, nmyip, IPSTATUS::USING, m_NICMACAddress);
	}

	// 라우트 상태 추가
	memcpy(&nsip, m_GatewayIPAddress, IPV4ADDRESSLENGTH);
	hsip = ntohl(nsip);
	if (hsip >= hbip && hsip <= heip)
	{
		index = hsip - hbip;
		m_vhIPStatusInfo.VectorSetItem(index, nsip, IPSTATUS::USING_GATEWAY, bli->shaddr);
	}

	// 캡처한 패킷 검사
	for (; bli != eli; bli++)
	{
		memcpy(&nsip, bli->spaddr, IPV4ADDRESSLENGTH);
		hsip = ntohl(nsip);

		switch (ntohs(bli->opcode))
		{
			// Request ARP 패킷
		case ARPOPCODE::ARPREQUEST:
		{
			// 내가 보낸 ARP Packet 버리기
			if (nsip == nmyip)
				continue;
			continue;
		}
		// Request ARP 패킷
		case ARPOPCODE::ARPREPLY:
		{
			// 패킷을 보낸 호스트의 IP가 검색 범위 안쪽일때
			if (hsip >= hbip && hsip <= heip)
			{
				index = hsip - hbip + addition;
				switch (m_vhIPStatusInfo[index].m_IPStatus)
				{
				case IPSTATUS::USING:			// 사용중일때
				case IPSTATUS::USING_GATEWAY:	// 게이트웨이
				case IPSTATUS::IPDUPLICATION:	// IP 충돌
				{
					// macaddress 관찰하여 동일한지 확인
					if (strncmp(reinterpret_cast<char*>(bli->shaddr), reinterpret_cast<char*>(m_vhIPStatusInfo[index].m_MACAddress), MACADDRESSLENGTH))
						continue;
					else
					{
						m_vhIPStatusInfo[index].m_IPStatus = IPSTATUS::IPDUPLICATION;
						// 중복 ip 추가 삽입
						m_vhIPStatusInfo.VectorInsertItem(index, nsip, IPSTATUS::IPDUPLICATION, bli->shaddr);
						addition++;
						continue;
					}
					break;
				}
				case IPSTATUS::OTHERNETWORK:	// 
				case IPSTATUS::UNKNOWN:			// 
					break;
				case IPSTATUS::NOTUSING:		// 사용중이지 않을 때 
					m_vhIPStatusInfo.VectorSetItem(index, nsip, IPSTATUS::USING, bli->shaddr);
					break;
				default:
					break;
				}
			}
			continue;
		}
		case ARPOPCODE::RARPREQUEST:
		case ARPOPCODE::RARPREPLY:
		case ARPOPCODE::DRARPREQUEST:
		case ARPOPCODE::DRARPREPLY:
		case ARPOPCODE::INARPREQUEST:
		case ARPOPCODE::INARPREPLY:
		default:
		{
			continue;
		}
		}
	}
}
