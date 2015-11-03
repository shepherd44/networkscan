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
	// ip ����Ʈ

	// ip 

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
	bool *isdye = (bool *)lpParam;
	while (1)
	{
		
		// ������ ���� Ȯ��
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
		throw std::exception("send thread ���� ����");
	}

	if (m_hSendThread == NULL)
		throw std::exception("������ ���� ����");
}

void CNetworkIPScan::EndSend()
{
	m_IsSendThreadDye = TRUE;
	WaitForSingleObject(m_hSendThread->m_hThread, INFINITE);
	m_hSendThread = NULL;
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
			ipstatlist->UpdateItem(index, ip, mac, USING, TRUE);
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
	m_CaptureSock.EndCapture();
	WaitForSingleObject(m_hCaptureThread->m_hThread, INFINITE);
	m_hCaptureThread = NULL;
}