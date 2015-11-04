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
	CNetworkScannerDlg *maindlg = (CNetworkScannerDlg *)(AfxGetApp()->GetMainWnd());
	CWPcapSendSocket *sendsock = (CWPcapSendSocket *)((struct ThreadParams*)lpParam)->socket;
	bool *isdye = (bool *)((struct ThreadParams*)lpParam)->isend;
	CIPStatusList *iplist = (CIPStatusList *)((struct ThreadParams*)lpParam)->list;
	// 스레드 종료 확인
	if (*isdye)
		return 0;

	int size = iplist->GetSize();
	int i = 0;
	for (; i < size; i++)
	{
		// 스레드 종료 확인
		if (*isdye)
			return 0;
		sendsock->SendARPRequest(iplist->At(i)->IPAddress);
	}
	maindlg->ListCtrlUpdate();

	for (i = 0; i < size; i++)
	{
		// 스레드 종료 확인
		if (*isdye)
			return 0;
		sendsock->SendPingInWin(iplist->At(i)->IPAddress);
	}

	maindlg->ListCtrlUpdate();
	
	return 0;
}
void CNetworkIPScan::StartSend()
{
	static struct ThreadParams sendparam;
	if (m_hSendThread == NULL)
	{
		memset(&sendparam, 0, sizeof(struct ThreadParams));
		sendparam.socket = &m_SendSock;
		sendparam.isend = &m_IsSendThreadDye;
		sendparam.list = &m_IPStatInfoList;
		m_IsSendThreadDye = FALSE;
		m_hSendThread = AfxBeginThread(SendThreadFunc, &sendparam, 0, 0, 0);
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
	if (m_hSendThread != NULL)
	{
		m_IsSendThreadDye = TRUE;
		WaitForSingleObject(m_hSendThread->m_hThread, INFINITE);
		m_hSendThread = NULL;
	}
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
	struct ThreadParams *capparam = (struct ThreadParams *)param;
	CIPStatusList *ipstatlist = (CIPStatusList *)capparam->list;
	CWPcapCaptureSocket *capsock = (CWPcapCaptureSocket *)capparam->socket;

	uint32_t myip = capsock->GetCurrentSelectNICInfo()->NICIPAddress;
	ARPPacket *arpp = (ARPPacket *)(packet + ETHERNETHEADER_LENGTH);
	uint32_t dstip, senderip;
	int index;
	uint8_t mac[MACADDRESS_LENGTH] = { 0, };

	// 범위 내의 ip인지 확인
	memcpy(&senderip, arpp->spaddr, IPV4ADDRESS_LENGTH);
	index = ipstatlist->IsInItem(senderip);
	if (index == -1)
		return;

	// 패킷 분석
	switch (ntohs(arpp->opcode))
	{
	case ARPOPCODE::ARPREQUEST:
		if (senderip == myip)
			break;
		break;
	case ARPOPCODE::ARPREPLY:
		memcpy(&dstip, arpp->dpaddr, IPV4ADDRESS_LENGTH);
		if (dstip == myip)
		{
			memcpy(mac, arpp->shaddr, MACADDRESS_LENGTH);
			
			index = ipstatlist->IsInItem(senderip);
			IPStatusInfo *temp = ipstatlist->At(index);
			switch (temp->IPStatus)
			{
			case IPSTATUS::NOTUSING:
				ipstatlist->UpdateItemARPInfo(index, mac, USING);
				break;
			case IPSTATUS::USING:
			case IPSTATUS::USING_GATEWAY:
			case IPSTATUS::IPDUPLICATION:
				if (strncmp((char*)temp->MACAddress, (char*)mac, 6) == 0)
				{
					break;
				}
				else
				{
					ipstatlist->UpdateItemIPStat(index, IPDUPLICATION);
					ipstatlist->InsertItem(index, senderip, mac, IPDUPLICATION, FALSE);
				}
				break;
			default:
				break;
			}
		}
		break;
	default:
		break;
	}
}
void CNetworkIPScan::IPAnalyze(const uint8_t *param, const uint8_t *packet)
{
	// 파라미터 변환
	struct ThreadParams *capparam = (struct ThreadParams *)param;
	CIPStatusList *ipstatlist = (CIPStatusList *)capparam->list;
	CWPcapCaptureSocket *capsock = (CWPcapCaptureSocket *)capparam->socket;

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
			IPSTATUS status = ipstatlist->At(index)->IPStatus;
			if (status == IPSTATUS::NOTUSING)
				ipstatlist->UpdateItemPingStat(index, IPSTATUS::USING, TRUE);
			else
				ipstatlist->UpdateItemPingStat(index, status, TRUE);
		}
		break;
	default:
		break;
	}
}

// 쓰레드용 캡처 시작 함수 
UINT AFX_CDECL CNetworkIPScan::CaptureThreadFunc(LPVOID lpParam)
{
	struct ThreadParams *capparam = (struct ThreadParams *)lpParam;
	CWPcapCaptureSocket *capsock = (CWPcapCaptureSocket *)capparam->socket;
	capsock->StartCapture(Analyze, (uint8_t *)lpParam, 0, 0);
	return 0;
}

// 캡쳐 시작, 쓰레드 사용.
// EndCapture()로 종료
void CNetworkIPScan::StartCapture()
{
	// 캡쳐 스레드 파라미터
	static struct ThreadParams capparam;
	
	if (m_hCaptureThread == NULL)
	{
		memset(&capparam, 0, sizeof(struct ThreadParams));
		capparam.socket = &m_CaptureSock;
		capparam.list = &m_IPStatInfoList;

		// 캡쳐 스레드 시작
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
	if (m_hCaptureThread != NULL)
	{
		m_CaptureSock.EndCapture();
		WaitForSingleObject(m_hCaptureThread->m_hThread, INFINITE);
		m_hCaptureThread = NULL;
	}
}

void CNetworkIPScan::IPStatusListInsertItem(IPStatusInfo *ipstatinfo, uint32_t hbeginip, uint32_t hendip)
{

	/*for (; hbeginip <= hendip; hbeginip++)
	{
		int index = m_IPStatInfoList.IsInItem(htonl(hbeginip));
		if (index == -1)
			m_IPStatInfoList->InsertItem(htonl(hbeginip), mac, IPSTATUS::NOTUSING, false);
	}*/
}