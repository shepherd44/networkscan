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
	m_SendSock.FindNetDevice();
	m_hCaptureThread = NULL;
	m_hSendThread = NULL;
	CNetworkScannerDlg *MainDlg = (CNetworkScannerDlg *)AfxGetApp()->GetMainWnd();
	m_ListCtrlUpdate = &MainDlg->ListCtrlUpdate;
}

// 스캔 시작
void CNetworkIPScan::Scan(int nicindex)
{
	// ip 리스트

	// ip 

	// socket open
	m_SendSock.OpenNetDevice(nicindex);
	m_CaptureSock.OpenNetDevice(m_SendSock.GetCurrentSelectNICName());

	// 패킷 캡처 스레드 시작(분석 함께 함)
	StartCapture();

	// 패킷 전송 스레드 시작
	StartSend();


}

// 패킷 전송 스레드 함수
UINT AFX_CDECL CNetworkIPScan::SendThreadFunc(LPVOID lpParam)
{
	bool *isdye = (bool *)lpParam;
	while (1)
	{
		
		// 스레드 종료 확인
		if (*isdye)
			break;
	}
	return 0;
}

void CNetworkIPScan::StartSend()
{
	if (m_hSendThread == NULL)
	{
		m_IsSendThreadDye = FALSE;
		LPVOID param = &m_IsSendThreadDye;
		m_hSendThread = AfxBeginThread(SendThreadFunc, param, 0, 0, 0);
	}
	else
	{
		throw std::exception("send thread 생성 실패");
	}

	if (m_hSendThread == NULL)
		throw std::exception("스레드 시작 실패");
}

void CNetworkIPScan::EndSend()
{
	m_IsSendThreadDye = TRUE;
	WaitForSingleObject(m_hSendThread->m_hThread, INFINITE);
	m_hSendThread = NULL;
}

// 캡처 결과 분석, icmp, arp만 분석
// WPcapCaptureSocket.StartCapture의 콜백함수로 들어감
void CNetworkIPScan::Analyze(const uint8_t *param, const uint8_t *packet)
{
	ETHHeader *ethh = (ETHHeader *)packet;
	switch (ntohs(ethh->prototype))
	{
	case ETHTYPE::ARP:
		ARPAnalyze(param, const_cast<uint8_t *>(packet));
		break;
	case ETHTYPE::IPV4:
		IPAnalyze(param, const_cast<uint8_t *>(packet));
		break;
	default:
		break;
	}
}
void CNetworkIPScan::ARPAnalyze(const uint8_t *param, const uint8_t *packet)
{
	// 파라미터 변환
	struct CaptureParam *capparam = (struct CaptureParam *)param;
	CIPStatusList *ipstatlist = (CIPStatusList *)capparam->param_ipstatlist;
	CWPcapCaptureSocket *capsock = (CWPcapCaptureSocket *)capparam->param_capsock;

	//uint32_t nmyip = 
	//ARPPacket *arpp = (ARPPacket *)packet;
	//switch (ntohs(arpp->opcode))
	//{
	//	// Request ARP 패킷
	//case ARPOPCODE::ARPREQUEST:
	//{
	//	// 내가 보낸 ARP Packet 버리기
	//	if (nsip == nmyip)
	//		continue;
	//	continue;
	//}
	//// Request ARP 패킷
	//case ARPOPCODE::ARPREPLY:
	//{
	//	// 패킷을 보낸 호스트의 IP가 검색 범위 안쪽일때
	//	if (hsip >= hbip && hsip <= heip)
	//	{
	//		index = hsip - hbip + addition;
	//		switch (m_vhIPStatusInfo[index].m_IPStatus)
	//		{
	//		case IPSTATUS::USING:			// 사용중일때
	//		case IPSTATUS::USING_GATEWAY:	// 게이트웨이
	//		case IPSTATUS::IPDUPLICATION:	// IP 충돌
	//		{
	//			// macaddress 관찰하여 동일한지 확인
	//			if (strncmp(reinterpret_cast<char*>(bli->shaddr), reinterpret_cast<char*>(m_vhIPStatusInfo[index].m_MACAddress), MACADDRESSLENGTH))
	//				continue;
	//			else
	//			{
	//				m_vhIPStatusInfo[index].m_IPStatus = IPSTATUS::IPDUPLICATION;
	//				// 중복 ip 추가 삽입
	//				m_vhIPStatusInfo.VectorInsertItem(index, nsip, IPSTATUS::IPDUPLICATION, bli->shaddr);
	//				addition++;
	//				continue;
	//			}
	//			break;
	//		}
	//		case IPSTATUS::OTHERNETWORK:	// 
	//		case IPSTATUS::UNKNOWN:			// 
	//			break;
	//		case IPSTATUS::NOTUSING:		// 사용중이지 않을 때 
	//			m_vhIPStatusInfo.VectorSetItem(index, nsip, IPSTATUS::USING, bli->shaddr);
	//			break;
	//		default:
	//			break;
	//		}
	//	}
	//}
}

void CNetworkIPScan::IPAnalyze(const uint8_t *param, const uint8_t *packet)
{
	// 파라미터 변환
	struct CaptureParam *capparam = (struct CaptureParam *)param;
	CIPStatusList *ipstatlist = (CIPStatusList *)capparam->param_ipstatlist;
	CWPcapCaptureSocket *capsock = (CWPcapCaptureSocket *)capparam->param_capsock;

	IPV4Header *iph = (IPV4Header *)(packet + ETHERNETHEADER_LENGTH);
	uint32_t ip;
	int index;
	uint8_t mac[MACADDRESS_LENGTH] = { 0, };

	switch (iph->protoid)
	{
	case IPV4TYPE::ICMP:
		memcpy(&ip, iph->srcaddr, IPV4ADDRESS_LENGTH);
		index = ipstatlist->IsInItem(ip);
		if (index != -1)
		{
			//IPStatusInfo *ipstat = ipstatlist->At(index);
			//switch (ipstat->IPStatus)
			//{
			//case IPSTATUS::NOTUSING:

			//default:
			//	break;
			//}
			ipstatlist->UpdateItem(index, ip, mac, USING, TRUE);
		}
		break;
	default:
		break;
	}
	m_ListCtrlUpdate();
}


// 쓰레드용 캡처 시작 함수 
UINT AFX_CDECL CNetworkIPScan::CaptureThreadFunc(LPVOID lpParam)
{
	struct CaptureParam *capparam = (struct CaptureParam *)lpParam;
	CWPcapCaptureSocket *capsock = capparam->param_capsock;
	capsock->StartCapture(Analyze, (uint8_t *)lpParam, 0, 0);
	return 0;
}

// 캡쳐 시작, 쓰레드 사용.
// EndCapture()로 종료
void CNetworkIPScan::StartCapture()
{
	static struct CaptureParam capparam;
	
	if (m_hCaptureThread == NULL)
	{
		memset(&capparam, 0, sizeof(struct CaptureParam));
		capparam.param_capsock = &m_CaptureSock;
		capparam.param_ipstatlist = &m_IPStatInfoList;
		m_hCaptureThread = AfxBeginThread(CaptureThreadFunc, &capparam, 0, 0, 0);
	}
	else
	{
		throw std::exception("capture thread 생성 실패");
	}

	if (m_hCaptureThread == NULL)
		throw std::exception("스레드 시작 실패");
}

// 캡처 종료
void CNetworkIPScan::EndCapture()
{
	// 종료 신호 보내기
	m_CaptureSock.EndCapture();
	WaitForSingleObject(m_hCaptureThread->m_hThread, INFINITE);
	m_hCaptureThread = NULL;
}


//u_long nbip = m_BeginIP, neip = m_EndIP;	// 시작, 끝 ip (네트워크 정렬)
//u_long hbip = htonl(nbip), heip = htonl(neip);	// 시작, 끝 ip (호스트 정렬)
//
//// 분석
//std::list<ARPPacket>::iterator bli = m_ARPCaptureSock.GetCaptureListBegin();	// 캡쳐 결과 리스트 시작
//std::list<ARPPacket>::iterator eli = m_ARPCaptureSock.GetCaptureListEnd();		// 캡쳐 결과 리스트 끝

//u_long nmyip, hmyip;
//int index;
//int addition = 0;
//u_long nsip, hsip;

//memcpy(&nmyip, m_NICIPAddress, IPV4ADDRESSLENGTH);
//hmyip = ntohl(nmyip);
//// 내 IP 상태 추가
//if (hmyip >= hbip && hmyip <= heip)
//{
//	index = hmyip - hbip;
//	m_vhIPStatusInfo.VectorSetItem(index, nmyip, IPSTATUS::USING, m_NICMACAddress);
//}

//// 라우트 상태 추가
//memcpy(&nsip, m_GatewayIPAddress, IPV4ADDRESSLENGTH);
//hsip = ntohl(nsip);
//if (hsip >= hbip && hsip <= heip)
//{
//	index = hsip - hbip;
//	m_vhIPStatusInfo.VectorSetItem(index, nsip, IPSTATUS::USING_GATEWAY, bli->shaddr);
//}

//// 캡처한 패킷 검사
//for (; bli != eli; bli++)
//{
//	memcpy(&nsip, bli->spaddr, IPV4ADDRESSLENGTH);
//	hsip = ntohl(nsip);

//	switch (ntohs(bli->opcode))
//	{
//		// Request ARP 패킷
//	case ARPOPCODE::ARPREQUEST:
//	{
//		// 내가 보낸 ARP Packet 버리기
//		if (nsip == nmyip)
//			continue;
//		continue;
//	}
//	// Request ARP 패킷
//	case ARPOPCODE::ARPREPLY:
//	{
//		// 패킷을 보낸 호스트의 IP가 검색 범위 안쪽일때
//		if (hsip >= hbip && hsip <= heip)
//		{
//			index = hsip - hbip + addition;
//			switch (m_vhIPStatusInfo[index].m_IPStatus)
//			{
//			case IPSTATUS::USING:			// 사용중일때
//			case IPSTATUS::USING_GATEWAY:	// 게이트웨이
//			case IPSTATUS::IPDUPLICATION:	// IP 충돌
//			{
//				// macaddress 관찰하여 동일한지 확인
//				if (strncmp(reinterpret_cast<char*>(bli->shaddr), reinterpret_cast<char*>(m_vhIPStatusInfo[index].m_MACAddress), MACADDRESSLENGTH))
//					continue;
//				else
//				{
//					m_vhIPStatusInfo[index].m_IPStatus = IPSTATUS::IPDUPLICATION;
//					// 중복 ip 추가 삽입
//					m_vhIPStatusInfo.VectorInsertItem(index, nsip, IPSTATUS::IPDUPLICATION, bli->shaddr);
//					addition++;
//					continue;
//				}
//				break;
//			}
//			case IPSTATUS::OTHERNETWORK:	// 
//			case IPSTATUS::UNKNOWN:			// 
//				break;
//			case IPSTATUS::NOTUSING:		// 사용중이지 않을 때 
//				m_vhIPStatusInfo.VectorSetItem(index, nsip, IPSTATUS::USING, bli->shaddr);
//				break;
//			default:
//				break;
//			}
//		}
//		continue;
//	}
//	case ARPOPCODE::RARPREQUEST:
//	case ARPOPCODE::RARPREPLY:
//	case ARPOPCODE::DRARPREQUEST:
//	case ARPOPCODE::DRARPREPLY:
//	case ARPOPCODE::INARPREQUEST:
//	case ARPOPCODE::INARPREPLY:
//	default:
//	{
//		continue;
//	}
//	}
//}