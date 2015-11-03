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
			ipstatlist->UpdateItem(index, ip, mac, USING, TRUE);
		}
		break;
	default:
		break;
	}
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