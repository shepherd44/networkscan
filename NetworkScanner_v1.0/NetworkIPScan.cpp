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
	m_SendInterval = 1000;
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
	// 캡처소켓 필터 셋팅
	m_CaptureSock.SetPacketFilter("arp or icmp");

	// 내 PC IP 상태 처리
	NICInfo *nicinfo = const_cast<NICInfo *>(m_SendSock.GetCurrentSelectNICInfo());
	int index = m_IPStatInfoList.IsInItem(nicinfo->NICIPAddress);
	IPStatusInfo* ipstat;
	if (index != -1)
	{
		ipstat = m_IPStatInfoList.GetItem(index);
		ipstat->IPAddress = nicinfo->NICIPAddress;
		memcpy(ipstat->MACAddress, nicinfo->NICMACAddress, MACADDRESS_LENGTH);
		ipstat->IPStatus = IPSTATUS::USING;
	}
		

	// GateWayIP 상태 처리
	uint8_t mac[MACADDRESS_LENGTH] = { 0, };
	index = m_IPStatInfoList.IsInItem(nicinfo->GatewayIPAddress);
	if (index != -1)
	{
		// Gateway Mac 주소 얻어오기;
		m_SendSock.GetDstMAC(mac, nicinfo->GatewayIPAddress, 1000);
		// ipstatus 설정
		ipstat = m_IPStatInfoList.GetItem(index);
		ipstat->IPAddress = nicinfo->GatewayIPAddress;
		memcpy(ipstat->MACAddress, mac, MACADDRESS_LENGTH);
		ipstat->IPStatus = IPSTATUS::USING_GATEWAY;
	}
		
	// 패킷 캡처 스레드 시작(분석 함께 함)
	StartCapture();

	// 패킷 전송 스레드 시작
	StartSend();
}


int gettimeofday(struct timeval *tv, struct timeval *tz)
{
	struct _timeb timebuffer;

	_ftime(&timebuffer);

	tv->tv_sec = (long)timebuffer.time;
	tv->tv_usec = timebuffer.millitm * 1000;
	return 0;
};

// 패킷 전송 스레드 함수
UINT AFX_CDECL CNetworkIPScan::SendThreadFunc(LPVOID lpParam)
{
	// 파라미터 가져오기
	CNetworkIPScan *scanner = (CNetworkIPScan *)lpParam;
	CNetworkScannerDlg *maindlg = (CNetworkScannerDlg *)(AfxGetApp()->GetMainWnd());
	CWPcapSendSocket *sendsock = scanner->GetSendSocket();
	bool *isdye = (bool *)&scanner->m_IsSendThreadDye;
	CIPStatusList *iplist = (CIPStatusList *)scanner->GetIpStatusList();
	IPStatusInfo *ipstat = NULL;

	// 네트워크 주소 계산
	NICInfo *nicinfo = const_cast<NICInfo *>(sendsock->GetCurrentSelectNICInfo());
	// 호스트의 주소체계를 사용하면 h를 붙여둠
	uint32_t hnetmask = ntohl(nicinfo->Netmask);
	uint32_t hstartnetwork = hnetmask & ntohl(nicinfo->NICIPAddress);
	uint32_t hendnetwork = hstartnetwork + ~hnetmask;
	uint32_t ip, hip;
	
	timeval now;
	while (!*isdye)
	{
		// 프로그램 상태바 업데이트
		maindlg->SetProgramState(SCANNIG_STATE::SCANNING_ARPSEND);
		int size = iplist->GetSize();
		int i = 0;
		// ARP 전송
		for (; i < size; i++)
		{
			// 스레드 종료 확인
			if (*isdye)
				return 0;
			ipstat = iplist->GetItem(i);
			ip = ipstat->IPAddress;
			hip = ntohl(ip);
			if (hip >= hstartnetwork && hip <= hendnetwork)
			{
				gettimeofday(&now, NULL);
				sendsock->SendARPRequest(ip);
				ipstat->LastARPSendTime = now;
			}
		}

		// ARP 보낸 뒤 대기
		for (i = 0; i < scanner->GetSendInterval() / 10; i++)
		{
			if (*isdye)
				return 0;
			Sleep(10);
		}
		maindlg->SetProgramState(SCANNIG_STATE::SCANNING_PINGSEND);

		for (i = 0; i < size; i++)
		{
			// 스레드 종료 확인
			if (*isdye)
				return 0;
			iplist->Lock(INFINITE);
			ipstat = iplist->GetItem(i);
			ip = ipstat->IPAddress;
			iplist->Unlock();
			hip = ntohl(ip);

			gettimeofday(&now, NULL);
			sendsock->SendICMPV4ECHORequest(ip);
			ipstat->LastPingSendTime = now;
			size = iplist->GetSize();
		}

		for (i = 0; i < scanner->GetSendInterval() / 10; i++)
		{
			if (*isdye)
				return 0;
			Sleep(10);
		}
	}

	maindlg->SetProgramState(SCANNIG_STATE::SCANNING_SENDINGCOMPLETE);

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
		m_hSendThread = AfxBeginThread(SendThreadFunc, this, 0, 0, 0);
	}
	else
	{
		throw std::exception("send thread 생성 실패");
#ifdef _DEBUG
		AfxMessageBox(L"send thread 생성실패");
#endif // _DEBUG
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
		m_SendSock.CloseNetDevice();
		m_SendSock.FindNetDevice();
	}
}

// 캡처 결과 분석, icmp, arp만 분석
// WPcapCaptureSocket.StartCapture의 콜백함수로 들어감
void CNetworkIPScan::Analyze(const uint8_t *param, const uint8_t *packet, const uint8_t *pkthdr)
{
	ETHHeader *ethh = (ETHHeader *)packet;
	switch (ntohs(ethh->prototype))
	{
	case ETHTYPE::ARP:
		ARPAnalyze(param, const_cast<uint8_t *>(packet), pkthdr);
		break;
	case ETHTYPE::IPV4:
		IPAnalyze(param, const_cast<uint8_t *>(packet), pkthdr);
		break;
	default:
		break;
	}
}
void CNetworkIPScan::ARPAnalyze(const uint8_t *param, const uint8_t *packet, const uint8_t *pkthdr)
{
	// 파라미터 변환
	struct ThreadParams *capparam = (struct ThreadParams *)param;
	CIPStatusList *ipstatlist = (CIPStatusList *)capparam->list;
	CWPcapCaptureSocket *capsock = (CWPcapCaptureSocket *)capparam->socket;
	struct pcap_pkthdr *packetheader = (struct pcap_pkthdr*) pkthdr;

	uint32_t myip = capsock->GetCurrentSelectNICInfo()->NICIPAddress;
	ARPPacket *arpp = (ARPPacket *)(packet + ETHERNETHEADER_LENGTH);
	uint32_t dstip, senderip;
	int index;
	uint8_t mac[MACADDRESS_LENGTH] = { 0, };

	// 스캔 범위 내의 ip인지 확인한다.
	IPStatusInfo *ipstat;
	memcpy(&senderip, arpp->spaddr, IPV4ADDRESS_LENGTH);
	index = ipstatlist->IsInItem(senderip);
	if (index == -1)
		return;
	else
	{
		// IPStatusInfo 리스트에서 아이템 가져오기
		ipstat = ipstatlist->GetItem(index);
	}
		

	// ARP 패킷 분석
	switch (ntohs(arpp->opcode))
	{
	case ARPOPCODE::ARPREQUEST:
		if (senderip == myip)
		{
			break;
		}
		break;
	case ARPOPCODE::ARPREPLY:
		memcpy(&dstip, arpp->dpaddr, IPV4ADDRESS_LENGTH);
		if (dstip == myip)
		{
			memcpy(mac, arpp->shaddr, MACADDRESS_LENGTH);
			ipstat = ipstatlist->GetItem(index);
			switch (ipstat->IPStatus)
			{
			case IPSTATUS::NOTUSING:
			case IPSTATUS::ONLYPING:
				memcpy(ipstat->MACAddress, mac, MACADDRESS_LENGTH);
				ipstat->IPStatus = USING;
				ipstat->LastPingRecvTime = packetheader->ts;				
				break;
			case IPSTATUS::USING:
			case IPSTATUS::USING_GATEWAY:
				if (strncmp((char*)ipstat->MACAddress, (char*)mac, 6) == 0)
					break;
				else
				{
					ipstat->DuplicationMACCount++;
					ipstat->DuplicationMAC = new MACAddr[ipstat->DuplicationMACCount];
					memcpy(ipstat->DuplicationMAC, mac, MACADDRESS_LENGTH);
					ipstat->IPStatus = IPDUPLICATION;
				}
				break;
			case IPSTATUS::IPDUPLICATION:
				if (strncmp((char*)ipstat->MACAddress, (char*)mac, 6) == 0)
					break;
				// 맥 주소가 다를경우 IP 충돌 표시를 나타내고 MAC 목록을 추가한다.
				else
				{
					for (int i = 0; i < ipstat->DuplicationMACCount; i++)
					{
						if (strncmp((char*)ipstat->DuplicationMAC[i], (char*)mac, 6) == 0)
							continue;
						else
						{
							ipstat->DuplicationMACCount++;
							MACAddr *temp = new MACAddr[ipstat->DuplicationMACCount];
							memcpy(temp, mac, sizeof(MACAddr));
							memcpy(temp + sizeof(MACAddr), ipstat->DuplicationMAC, sizeof(MACAddr) * (ipstat->DuplicationMACCount - 1));
							delete(ipstat->DuplicationMAC);
							ipstat->DuplicationMAC = temp;
							break;
						}
					}
					break;
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
void CNetworkIPScan::IPAnalyze(const uint8_t *param, const uint8_t *packet, const uint8_t *pkthdr)
{
	// 파라미터 변환
	struct ThreadParams *capparam = (struct ThreadParams *)param;
	CIPStatusList *ipstatlist = (CIPStatusList *)capparam->list;
	CWPcapCaptureSocket *capsock = (CWPcapCaptureSocket *)capparam->socket;
	// pkthdr 카피
	struct pcap_pkthdr *packetheader = (struct pcap_pkthdr*) pkthdr;

	IPV4Header *iph = (IPV4Header *)(packet + ETHERNETHEADER_LENGTH);
	uint32_t ip;
	int index;
	uint8_t mac[MACADDRESS_LENGTH] = { 0, };

	memcpy(&ip, iph->srcaddr, IPV4ADDRESS_LENGTH);
	// 패킷 전송자가 나일 경우 리턴
	if (ip == capsock->GetCurrentSelectNICInfo()->NICIPAddress)
	{
		return;
	}
	

	// 패킷 전송자가 
	index = ipstatlist->IsInItem(ip);
	if (index == -1)
		return;

	// 있을 경우 IPStatus 상태에 따라 처리
	switch (iph->protoid)
	{
		case IPV4TYPE::ICMP:
		{
			IPStatusInfo *ipinfo = ipstatlist->GetItem(index);
			IPSTATUS status = ipinfo->IPStatus;

			// NOTUSING 상태일 경우 ONLYPING으로 바꾸고
			if (status == IPSTATUS::NOTUSING)
			{
				ipinfo->IPStatus = IPSTATUS::ONLYPING;
				ipinfo->PingReply = TRUE;
				ipinfo->LastPingRecvTime = packetheader->ts;
			}
					
			// 아닐경우 status를 그대로 가져간다.
			else
			{
				ipinfo->PingReply = TRUE;
				ipinfo->LastPingRecvTime = packetheader->ts;
			}
					
			break;
		}
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
		// 파라미터 셋팅
		memset(&capparam, 0, sizeof(struct ThreadParams));
		capparam.socket = &m_CaptureSock;
		capparam.list = &m_IPStatInfoList;

		// 캡쳐 스레드 시작
		m_hCaptureThread = AfxBeginThread(CaptureThreadFunc, &capparam, 0, 0, 0);
	}
	else
		throw std::exception("capture thread 생성 실패");

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
		m_CaptureSock.CloseNetDevice();
	}
}

void CNetworkIPScan::IPStatusListInsertItem(uint32_t hbeginip, uint32_t hendip)
{
	IPStatusInfo *item;
	int size = m_IPStatInfoList.GetSize();
	int index;
	int binary;
	int nip;
	uint8_t mac[MACADDRESS_LENGTH] = { 0, };
	for (; hbeginip <= hendip; hbeginip++)
	{
		int index = m_IPStatInfoList.SearchItemIndex(htonl(hbeginip));
		if (index == -1)
			continue;
		else
		{
			IPStatusInfo ipinfo;
			memset(&ipinfo, 0, sizeof(IPStatusInfo));
			ipinfo.DoARPPingSend = true;
			ipinfo.DoIPPingSend = true;
			ipinfo.IPAddress = htonl(hbeginip);
			memcpy(ipinfo.MACAddress, mac, MACADDRESS_LENGTH);
			ipinfo.IPStatus = IPSTATUS::NOTUSING;
			ipinfo.PingReply = false;

			m_IPStatInfoList.InsertItem(index, &ipinfo);
		}
	}
}

void CNetworkIPScan::IPStatusListDeleteItem(int index)
{
	m_IPStatInfoList.RemoveItem(index);
}