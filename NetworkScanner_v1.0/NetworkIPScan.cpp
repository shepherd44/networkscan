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

	// ��Ŷ ĸó ������ ����(�м� �Բ� ��)
	StartCapture();

	// ��Ŷ ���� ������ ����
	StartSend();


}

// ��Ŷ ���� ������ �Լ�
UINT AFX_CDECL CNetworkIPScan::SendThreadFunc(LPVOID lpParam)
{
	CWPcapSendSocket *sendsock = (CWPcapSendSocket *)((struct Params*)lpParam)->param1;
	bool *isdye = (bool *)((struct Params*)lpParam)->param2;
	CIPStatusList *iplist = (CIPStatusList *)((struct Params*)lpParam)->param3;
	// ������ ���� Ȯ��
	if (*isdye)
		return 0;
	int size = iplist->GetSize();
	int i = 0;
	for (; i < size; i++)
	{
		if (*isdye)
			return 0;
		sendsock->SendARPRequest(iplist->At(i)->IPAddress);
	}
	

	for (i = 0; i < size; i++)
	{
		if (*isdye)
			return 0;
		sendsock->SendPingInWin(iplist->At(i)->IPAddress);
	}
	
	CNetworkScannerDlg *maindlg = (CNetworkScannerDlg *)(AfxGetApp()->GetMainWnd());
	maindlg->ListCtrlUpdate();
	
	return 0;
}

void CNetworkIPScan::StartSend()
{
	static struct Params sendparam;
	if (m_hSendThread == NULL)
	{
		memset(&sendparam, 0, sizeof(struct Params));
		sendparam.param1 = &m_SendSock;
		sendparam.param2 = &m_IsSendThreadDye;
		sendparam.param3 = &m_IPStatInfoList;
		m_IsSendThreadDye = FALSE;
		m_hSendThread = AfxBeginThread(SendThreadFunc, &sendparam, 0, 0, 0);
	}
	else
	{
		throw std::exception("send thread ���� ����");
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
	struct CaptureParam *capparam = (struct CaptureParam *)param;
	CIPStatusList *ipstatlist = (CIPStatusList *)capparam->param_ipstatlist;
	CWPcapCaptureSocket *capsock = (CWPcapCaptureSocket *)capparam->param_capsock;

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
	// �Ķ���� ��ȯ
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


// ������� ĸó ���� �Լ� 
UINT AFX_CDECL CNetworkIPScan::CaptureThreadFunc(LPVOID lpParam)
{
	struct CaptureParam *capparam = (struct CaptureParam *)lpParam;
	CWPcapCaptureSocket *capsock = capparam->param_capsock;
	capsock->StartCapture(Analyze, (uint8_t *)lpParam, 0, 0);
	return 0;
}

// ĸ�� ����, ������ ���.
// EndCapture()�� ����
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
		throw std::exception("capture thread ���� ����");
	}

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
	}
}