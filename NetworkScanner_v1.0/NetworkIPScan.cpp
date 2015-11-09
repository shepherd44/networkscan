#include "stdafx.h"
#include "NetworkIPScan.h"

CNetworkIPScan::CNetworkIPScan()
{
	InitializeAll();
}
CNetworkIPScan::~CNetworkIPScan()
{
}

// �ʱ�ȭ �Լ�
void CNetworkIPScan::InitializeAll()
{
	m_SendInterval = 1000;
	m_SendSock.FindNetDevice();
	m_hCaptureThread = NULL;
	m_hSendThread = NULL;
}

// ��ĵ ����
void CNetworkIPScan::Scan(int nicindex)
{
	// socket open
	m_SendSock.OpenNetDevice(nicindex);
	m_CaptureSock.OpenNetDevice(m_SendSock.GetCurrentSelectNICName());
	m_CaptureSock.SetPacketFilter("arp and icmp");

	// NIC IP�� ��ĵ ���� �����̸� Ȯ�� �� ����
	NICInfo *nicinfo = const_cast<NICInfo *>(m_SendSock.GetCurrentSelectNICInfo());
	int index = m_IPStatInfoList.IsInItem(nicinfo->NICIPAddress);
	if (index != -1)
		m_IPStatInfoList.UpdateItem(index, nicinfo->NICIPAddress, nicinfo->NICMACAddress, IPSTATUS::USING, false);

	// GateWayIP�� ��ĵ ���� �����̸� Ȯ�� �� ����
	uint8_t mac[MACADDRESS_LENGTH] = { 0, };
	index = m_IPStatInfoList.IsInItem(nicinfo->GatewayIPAddress);
	if (index != -1)
	{
		m_SendSock.GetDstMAC(mac, nicinfo->GatewayIPAddress, 1000);
		m_IPStatInfoList.UpdateItem(index, nicinfo->GatewayIPAddress, mac, IPSTATUS::USING_GATEWAY, false);
	}
		
	// ��Ŷ ĸó ������ ����(�м� �Բ� ��)
	StartCapture();

	// ��Ŷ ���� ������ ����
	StartSend();

}

// ��Ŷ ���� ������ �Լ�
UINT AFX_CDECL CNetworkIPScan::SendThreadFunc(LPVOID lpParam)
{
	// �Ķ���� ��������
	CNetworkIPScan *scanner = (CNetworkIPScan *)lpParam;
	CNetworkScannerDlg *maindlg = (CNetworkScannerDlg *)(AfxGetApp()->GetMainWnd());
	CWPcapSendSocket *sendsock = scanner->GetSendSocket();
	bool *isdye = (bool *)&scanner->m_IsSendThreadDye;
	CIPStatusList *iplist = (CIPStatusList *)scanner->GetIpStatusList();
	
	// ��Ʈ��ũ �ּ� ���
	NICInfo *nicinfo = const_cast<NICInfo *>(sendsock->GetCurrentSelectNICInfo());
	uint32_t hnetmask = ntohl(nicinfo->Netmask);
	uint32_t hstartnetwork = hnetmask & ntohl(nicinfo->NICIPAddress);
	uint32_t hendnetwork = hstartnetwork + ~hnetmask;
	uint32_t ip, hip;
	
	while (1)
	{
		// ���α׷� ���¹� ������Ʈ
		maindlg->SetProgramState(SCANNIG_STATE::SCANNING_ARPSEND);
		int size = iplist->GetSize();
		int i = 0;
		for (; i < size; i++)
		{
			// ������ ���� Ȯ��
			if (*isdye)
				return 0;
			ip = iplist->At(i)->IPAddress;
			hip = ntohl(ip);
			if (hip >= hstartnetwork && hip <= hendnetwork)
				sendsock->SendARPRequest(ip);
		}

		// ARP ���� �� ���
		for (i = 0; i < scanner->GetSendInterval() / 10; i++)
		{
			if (*isdye)
				return 0;
			Sleep(10);
		}
		maindlg->SetProgramState(SCANNIG_STATE::SCANNING_PINGSEND);

		for (i = 0; i < size; i++)
		{
			// ������ ���� Ȯ��
			if (*isdye)
				return 0;
			ip = iplist->At(i)->IPAddress;
			hip = ntohl(ip);
			sendsock->SendICMPV4ECHORequest(ip);
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
		throw std::exception("send thread ���� ����");
#ifdef _DEBUG
		AfxMessageBox(L"send thread ��������");
#endif // _DEBUG
	}

	if (m_hSendThread == NULL)
		throw std::exception("������ ���� ����");
}
void CNetworkIPScan::EndSend()
{
	if (m_hSendThread != NULL)
	{
		m_IsSendThreadDye = TRUE;
		WaitForSingleObject(m_hSendThread->m_hThread, INFINITE);
		m_hSendThread = NULL;
		m_SendSock.CloseNetDevice();
	}
}

// ĸó ��� �м�, icmp, arp�� �м�
// WPcapCaptureSocket.StartCapture�� �ݹ��Լ��� ��
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
	// �Ķ���� ��ȯ
	struct ThreadParams *capparam = (struct ThreadParams *)param;
	CIPStatusList *ipstatlist = (CIPStatusList *)capparam->list;
	CWPcapCaptureSocket *capsock = (CWPcapCaptureSocket *)capparam->socket;

	uint32_t myip = capsock->GetCurrentSelectNICInfo()->NICIPAddress;
	ARPPacket *arpp = (ARPPacket *)(packet + ETHERNETHEADER_LENGTH);
	uint32_t dstip, senderip;
	int index;
	uint8_t mac[MACADDRESS_LENGTH] = { 0, };

	// ���� ���� ip���� Ȯ��
	memcpy(&senderip, arpp->spaddr, IPV4ADDRESS_LENGTH);
	index = ipstatlist->IsInItem(senderip);
	if (index == -1)
		return;

	// ��Ŷ �м�
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
			IPStatusInfo *item = ipstatlist->At(index);
			switch (item->IPStatus)
			{
			case IPSTATUS::NOTUSING:
			case IPSTATUS::ONLYPING:
				ipstatlist->UpdateItemARPInfo(index, mac, USING);
				break;
			case IPSTATUS::USING:
			case IPSTATUS::USING_GATEWAY:
			case IPSTATUS::IPDUPLICATION:
				if (strncmp((char*)item->MACAddress, (char*)mac, 6) == 0)
					break;
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
	// �Ķ���� ��ȯ
	struct ThreadParams *capparam = (struct ThreadParams *)param;
	CIPStatusList *ipstatlist = (CIPStatusList *)capparam->list;
	CWPcapCaptureSocket *capsock = (CWPcapCaptureSocket *)capparam->socket;

	IPV4Header *iph = (IPV4Header *)(packet + ETHERNETHEADER_LENGTH);
	uint32_t ip;
	int index;
	uint8_t mac[MACADDRESS_LENGTH] = { 0, };

	// ��Ŷ ����ip�� ��� ����Ʈ �ȿ� �ִ��� Ȯ��
	memcpy(&ip, iph->srcaddr, IPV4ADDRESS_LENGTH);

	if (ip == capsock->GetCurrentSelectNICInfo()->NICIPAddress)
		return;
	index = ipstatlist->IsInItem(ip);
	if (index == -1)
		return;

	else
	{
		switch (iph->protoid)
		{
			case IPV4TYPE::ICMP:
			{
				IPSTATUS status = ipstatlist->At(index)->IPStatus;

				// NOTUSING ������ ��� ONLYPING���� �ٲٰ�
				if (status == IPSTATUS::NOTUSING)
					ipstatlist->UpdateItemPingStat(index, IPSTATUS::ONLYPING, TRUE);
				// �ƴҰ�� status�� �״�� ��������.
				else
					ipstatlist->UpdateItemPingStat(index, status, TRUE);
				break;
			}
			default:
				break;
		}
	}
}

// ������� ĸó ���� �Լ� 
UINT AFX_CDECL CNetworkIPScan::CaptureThreadFunc(LPVOID lpParam)
{
	struct ThreadParams *capparam = (struct ThreadParams *)lpParam;
	CWPcapCaptureSocket *capsock = (CWPcapCaptureSocket *)capparam->socket;
	capsock->StartCapture(Analyze, (uint8_t *)lpParam, 0, 0);
	return 0;
}

// ĸ�� ����, ������ ���.
// EndCapture()�� ����
void CNetworkIPScan::StartCapture()
{
	// ĸ�� ������ �Ķ����
	static struct ThreadParams capparam;
	
	if (m_hCaptureThread == NULL)
	{
		// �Ķ���� ����
		memset(&capparam, 0, sizeof(struct ThreadParams));
		capparam.socket = &m_CaptureSock;
		capparam.list = &m_IPStatInfoList;

		// ĸ�� ������ ����
		m_hCaptureThread = AfxBeginThread(CaptureThreadFunc, &capparam, 0, 0, 0);
	}
	else
		throw std::exception("capture thread ���� ����");

	if (m_hCaptureThread == NULL)
		throw std::exception("������ ���� ����");
}

// ĸó ����
void CNetworkIPScan::EndCapture()
{
	// ���� ��ȣ ������
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
			m_IPStatInfoList.InsertItem(index, htonl(hbeginip), mac, IPSTATUS::NOTUSING, false);
	}
}

void CNetworkIPScan::IPStatusListDeleteItem(int index)
{
	m_IPStatInfoList.RemoveItem(index);
}