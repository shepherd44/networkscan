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
	HANDLE m_hCaptureThread = NULL;
	AdapterInfoInit();
}

// �ƴ��� ���� �ʱ�ȭ
// �ʱ�ȭ ���: NIC IP, NIC MAC, Gateway IP
void CNetworkIPScan::AdapterInfoInit()
{
	DWORD size = sizeof(PIP_ADAPTER_INFO);
	int ss = sizeof(IP_ADAPTER_INFO);
	u_long ipaddr;
	PIP_ADAPTER_INFO Info;
	ZeroMemory(&Info, size);

	// ��Ʈ��ũ �������̽� ���� ��������
	int result = GetAdaptersInfo(Info, &size);
	if (result == ERROR_BUFFER_OVERFLOW)
	{
		Info = (PIP_ADAPTER_INFO)malloc(size);
		GetAdaptersInfo(Info, &size);
	}

	// NIC MAC �ּ�
	memcpy(m_NICMACAddress, Info->Address, MACADDRESSLENGTH);
	// NIC IP �ּ�
	ipaddr = inet_addr(Info->IpAddressList.IpAddress.String);
	memcpy(m_NICIPAddress, &ipaddr, IPV4ADDRESSLENGTH);
	// NIC Netmask
	ipaddr = inet_addr(Info->IpAddressList.IpMask.String);
	memcpy(m_NICNetmask, &ipaddr, IPV4ADDRESSLENGTH);
	// Gateway IP �ּ�
	ipaddr = inet_addr(Info->GatewayList.IpAddress.String);
	memcpy(m_GatewayIPAddress, &ipaddr, IPV4ADDRESSLENGTH);

	// �ƴ��� ���� ����
	free(Info);
}

// ��ĵ ����
void CNetworkIPScan::Scan(u_long hbeginip, u_long hendip)
{
	// �Էµ� IP �ּ� ó��
	u_long size = 0;
	m_BeginIP = htonl(hbeginip);
	m_EndIP = htonl(hendip);

	// ���� ���� �ʱ�ȭ
	size = hendip - hbeginip + 1;
	m_vhIPStatusInfo.VectorResize(size);

	// ��ĵ ���� ( ARP Capture )
	StartCapture();
	// ARP ��Ŷ �۽�
	SendARP(m_BeginIP, m_EndIP);
	// ��Ŷ ĸ�� ��ٸ���
	Sleep(1000);
	// ĸ�� ������
	EndCapture();
	// �м�
	Analyze();
}

// ������ ������ IP�� ARP ��û
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

// ������� ĸó ���� �Լ� 
DWORD WINAPI CNetworkIPScan::ARPCaptueThreadFunc(LPVOID lpParam)
{
	CARPSocket *arpsock = (CARPSocket *)lpParam;
	arpsock->StartCapture();
	return 0;
}

// ĸ�� ����, ������ ���.
// EndCapture()�� ����
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
		throw std::exception("������ ���� ����");
}

// ĸó ����
void CNetworkIPScan::EndCapture()
{
	// ���� ��ȣ ������
	m_ARPCaptureSock.EndCapture();
	// ������ �ڵ� �ݱ�
	CloseHandle(m_hCaptureThread);
}

// ĸó ��� �м�
void CNetworkIPScan::Analyze()
{
	u_long nbip = m_BeginIP, neip = m_EndIP;	// ����, �� ip (��Ʈ��ũ ����)
	u_long hbip = htonl(nbip), heip = htonl(neip);	// ����, �� ip (ȣ��Ʈ ����)
	
	// �м�
	std::list<ARPPacket>::iterator bli = m_ARPCaptureSock.GetCaptureListBegin();	// ĸ�� ��� ����Ʈ ����
	std::list<ARPPacket>::iterator eli = m_ARPCaptureSock.GetCaptureListEnd();		// ĸ�� ��� ����Ʈ ��

	u_long nmyip, hmyip;
	int index;
	int addition = 0;
	u_long nsip, hsip;

	memcpy(&nmyip, m_NICIPAddress, IPV4ADDRESSLENGTH);
	hmyip = ntohl(nmyip);
	// �� IP ���� �߰�
	if (hmyip >= hbip && hmyip <= heip)
	{
		index = hmyip - hbip;
		m_vhIPStatusInfo.VectorSetItem(index, nmyip, IPSTATUS::USING, m_NICMACAddress);
	}

	// ���Ʈ ���� �߰�
	memcpy(&nsip, m_GatewayIPAddress, IPV4ADDRESSLENGTH);
	hsip = ntohl(nsip);
	if (hsip >= hbip && hsip <= heip)
	{
		index = hsip - hbip;
		m_vhIPStatusInfo.VectorSetItem(index, nsip, IPSTATUS::USING_GATEWAY, bli->shaddr);
	}

	// ĸó�� ��Ŷ �˻�
	for (; bli != eli; bli++)
	{
		memcpy(&nsip, bli->spaddr, IPV4ADDRESSLENGTH);
		hsip = ntohl(nsip);

		switch (ntohs(bli->opcode))
		{
			// Request ARP ��Ŷ
		case ARPOPCODE::ARPREQUEST:
		{
			// ���� ���� ARP Packet ������
			if (nsip == nmyip)
				continue;
			continue;
		}
		// Request ARP ��Ŷ
		case ARPOPCODE::ARPREPLY:
		{
			// ��Ŷ�� ���� ȣ��Ʈ�� IP�� �˻� ���� �����϶�
			if (hsip >= hbip && hsip <= heip)
			{
				index = hsip - hbip + addition;
				switch (m_vhIPStatusInfo[index].m_IPStatus)
				{
				case IPSTATUS::USING:			// ������϶�
				case IPSTATUS::USING_GATEWAY:	// ����Ʈ����
				case IPSTATUS::IPDUPLICATION:	// IP �浹
				{
					// macaddress �����Ͽ� �������� Ȯ��
					if (strncmp(reinterpret_cast<char*>(bli->shaddr), reinterpret_cast<char*>(m_vhIPStatusInfo[index].m_MACAddress), MACADDRESSLENGTH))
						continue;
					else
					{
						m_vhIPStatusInfo[index].m_IPStatus = IPSTATUS::IPDUPLICATION;
						// �ߺ� ip �߰� ����
						m_vhIPStatusInfo.VectorInsertItem(index, nsip, IPSTATUS::IPDUPLICATION, bli->shaddr);
						addition++;
						continue;
					}
					break;
				}
				case IPSTATUS::OTHERNETWORK:	// 
				case IPSTATUS::UNKNOWN:			// 
					break;
				case IPSTATUS::NOTUSING:		// ��������� ���� �� 
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
