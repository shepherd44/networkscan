#include "stdafx.h"
#include "ARPSocket.h"

// ������
CARPSocket::CARPSocket()
{
	SockInit();
}


CARPSocket::~CARPSocket()
{
	pcap_freealldevs(m_pNetDevice);
	pcap_close(m_pCapHandler);
	
}

// �ʱ�ȭ �Լ�
void CARPSocket::SockInit()
{
	m_pPacketFilter = "arp";
	m_pCapHandler = NULL;
	m_pNetDevice = NULL;
	m_CatureTime = 3;
	memset(m_ErrBuffer, '\0', sizeof(m_ErrBuffer));
	FindNetDevice();
	GetNICInfo();
	OpenNetDevice();
}

// winpcap ��Ŷ ĸ�� �ݹ� �Լ�
void CARPSocket::ARPCaptureCallBack(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ARPPacket *arppacket;
	static int cap_num = 0;
	// ARP ��� ��ġ ������.
	// arppacket = reinterpret_cast<ARPPacket *>(const_cast<u_char *>(pkt_data) + ETHERNETHEADERLENGTH);
	arppacket = (ARPPacket *)(pkt_data + ETHERNETHEADERLENGTH);
	// ĸó ��� ����Ʈ�� ����

	std::list<ARPPacket> *listtemp = reinterpret_cast<std::list<ARPPacket> *>(param);
	listtemp->push_back(*arppacket);
}

// �۵����� ��Ʈ��ũ ����̽� ã��
void CARPSocket::FindNetDevice()
{
	if (pcap_findalldevs(&m_pNetDevice, m_ErrBuffer) == -1)
	{
		throw std::exception("DeviceFindError\n");
	}
	int i = 0;
	for (pcap_if_t *d = m_pNetDevice; d; d = d->next)
		i++;
	if (i == 0)
		throw std::exception("No Network Interface Found\n");
}

// ��Ʈ��ũ �������̽� ����
void CARPSocket::OpenNetDevice()
{
	m_pCapHandler = pcap_open_live(m_pNetDevice->name, 65536, 1, 1000, m_ErrBuffer);
}

// ��Ʈ��ũ �������̽� ���� ���
// MAC, IP, NETMASK
void CARPSocket::GetNICInfo()
{
	DWORD size = sizeof(PIP_ADAPTER_INFO);
	PIP_ADAPTER_INFO Info;
	ZeroMemory(&Info, size);
	
	// ��Ʈ��ũ �������̽� ���� ��������
	int result = GetAdaptersInfo(Info, &size);
	if (result == ERROR_BUFFER_OVERFLOW)
	{
		Info = (PIP_ADAPTER_INFO)malloc(size);
		GetAdaptersInfo(Info, &size);
	}
	
	// ��Ʈ��ũ �������̽� MAC �ּ�
	memcpy(m_MyMACAddress, Info->Address, 6);
	// ��Ʈ��ũ �������̽� IP �ּ�
	u_long ipaddr = inet_addr(Info->IpAddressList.IpAddress.String);
	memcpy(m_MyIPAddress, &ipaddr, 4);
	// ��Ʈ��ũ �������̽� Netmask
	u_long netmask = inet_addr(Info->IpAddressList.IpMask.String);
	memcpy(&m_Netmask, &netmask, 4);

	free(Info);
}

// ethernet Header ����
void CARPSocket::SetEthHeader(u_char *out, u_char *srcmac, u_char *dstmac)
{
	u_int16_t ptype = htons(PROTOCOLTYPE::ARP);	//�������� Ÿ�� ARP�� ����

	memcpy(out, dstmac, MACADDRESSLENGTH);						// ������ �ϵ���� �ּ�
	memcpy(out + MACADDRESSLENGTH, srcmac, MACADDRESSLENGTH);	// �۽��� �ϵ���� �ּ�
	memcpy(out + (MACADDRESSLENGTH * 2), &ptype, 2);			// �������� Ÿ��
}

// ARP Packet ����
void CARPSocket::SetARPPacket(u_char *out, u_char *srcmac, u_char *srcip, u_char *dstmac, u_char *dstip)
{
	ARPPacket arppacket;
	memset(&arppacket, 0, sizeof(ARPPacket));
	int arplen = sizeof(ARPPacket);

	// arppacket �����
	arppacket.htype = htons(ARPHRD::ETHERNET);			// �ϵ���� Ÿ��
	arppacket.ptype = htons(PROTOCOLTYPE::IPV4);		// �������� Ÿ��
	arppacket.hlen = MACADDRESSLENGTH;					// �ϵ���� �ּ� ����
	arppacket.plen = IPV4ADDRESSLENGTH;					// �������� �ּ� ����
	arppacket.opcode = htons(ARPOPCODE::ARPREQUEST);	// ARP OPCODE
	memcpy(arppacket.shaddr, srcmac, MACADDRESSLENGTH);	// �۽��� �ϵ���� �ּ� ����
	memcpy(arppacket.spaddr, srcip, IPV4ADDRESSLENGTH);	// �۽��� IP address ����
	memcpy(arppacket.dhaddr, dstmac, MACADDRESSLENGTH);	// ������ �ϵ���� �ּ� ����
	memcpy(arppacket.dpaddr, dstip, IPV4ADDRESSLENGTH);	// ������ ip address ����

	// ��Ŷ ����
	memcpy(out, &arppacket, arplen);
}

// ��Ŷ ������
int CARPSocket::SendPacket(u_long dstip)
{
	u_char ethframe[ARPPACKETSIZE];
	u_char dstmac[MACADDRESSLENGTH];
	memset(ethframe, 0, ARPPACKETSIZE);

	memset(dstmac, 0xff, MACADDRESSLENGTH);		// ��ε� ĳ���� �ּ�
	// �̴��� ������ ��� ����
	SetEthHeader(ethframe,
				 m_MyMACAddress,
				 dstmac);

	memset(dstmac, 0x00, MACADDRESSLENGTH);		// �� �ּ�
	// ARP ��Ŷ ����
	SetARPPacket(ethframe + ETHERNETHEADERLENGTH,
				 m_MyMACAddress,
				 m_MyIPAddress,
				 dstmac,
				 (u_char *)(&dstip));

	// ��Ŷ ������
	int ret = pcap_sendpacket(m_pCapHandler, (u_char*)&ethframe, ARPPACKETSIZE);
	return ret;
}

// ��Ŷ ������
int CARPSocket::SendPacket(u_long srcip, u_long dstip)
{
	u_char ethframe[ARPPACKETSIZE];
	u_char dstmac[MACADDRESSLENGTH];
	memset(ethframe, 0, ARPPACKETSIZE);
	
	memset(dstmac, 0xff, MACADDRESSLENGTH);		// ��ε� ĳ���� �ּ�
	// �̴��� ������ ��� ����
	SetEthHeader(ethframe,
				 m_MyMACAddress,
				 dstmac);

	memset(dstmac, 0x00, MACADDRESSLENGTH);		// �� �ּ�
	// ARP ��Ŷ ����
	SetARPPacket(ethframe + ETHERNETHEADERLENGTH,
				 m_MyMACAddress,
				 (u_char *)(&srcip),
				 dstmac,
				 (u_char *)(&dstip));

	// ��Ŷ ������
	int ret = pcap_sendpacket(m_pCapHandler, (u_char*)&ethframe, ARPPACKETSIZE);
	return ret;
}

// ��Ŷ ĸ��
void CARPSocket::StartCapture(int pckcnt)
{
	// ��� ����
	m_LHCapturedPacket.clear();

	// Winpcap ARP ���� ����
	/*if (m_pNetDevice->addresses != NULL)
		m_Netmask = ((struct sockaddr_in *)(m_pNetDevice->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		m_Netmask = 0xffffff;*/

	pcap_compile(m_pCapHandler, &m_FilterCode, m_pPacketFilter, 1, m_Netmask);
	pcap_setfilter(m_pCapHandler, &m_FilterCode);

	pcap_loop(m_pCapHandler, pckcnt, CARPSocket::ARPCaptureCallBack, (u_char *)&m_LHCapturedPacket);
}

void CARPSocket::EndCapture()
{
	pcap_breakloop(m_pCapHandler);
	pcap_freecode(&m_FilterCode);
}

ARPPacket CARPSocket::GetARPPacket(int index)
{
	if (static_cast<u_int>(index) > m_LHCapturedPacket.size())
		throw std::exception("�ʹ� ū �ε���");
	std::list<ARPPacket>::iterator li = m_LHCapturedPacket.begin();
	for (int i = 0; i < index; li++, i++);
	return *li;
}
