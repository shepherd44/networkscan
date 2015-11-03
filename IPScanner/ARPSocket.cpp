#include "stdafx.h"
#include "ARPSocket.h"

// 생성자
CARPSocket::CARPSocket()
{
	SockInit();
}


CARPSocket::~CARPSocket()
{
	pcap_freealldevs(m_pNetDevice);
	pcap_close(m_pCapHandler);
	
}

// 초기화 함수
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

// winpcap 패킷 캡쳐 콜백 함수
void CARPSocket::ARPCaptureCallBack(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ARPPacket *arppacket;
	static int cap_num = 0;
	// ARP 헤더 위치 포인팅.
	// arppacket = reinterpret_cast<ARPPacket *>(const_cast<u_char *>(pkt_data) + ETHERNETHEADERLENGTH);
	arppacket = (ARPPacket *)(pkt_data + ETHERNETHEADERLENGTH);
	// 캡처 결과 리스트에 저장

	std::list<ARPPacket> *listtemp = reinterpret_cast<std::list<ARPPacket> *>(param);
	listtemp->push_back(*arppacket);
}

// 작동중인 네트워크 디바이스 찾기
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

// 네트워크 인터페이스 연결
void CARPSocket::OpenNetDevice()
{
	m_pCapHandler = pcap_open_live(m_pNetDevice->name, 65536, 1, 1000, m_ErrBuffer);
}

// 네트워크 인터페이스 정보 얻기
// MAC, IP, NETMASK
void CARPSocket::GetNICInfo()
{
	DWORD size = sizeof(PIP_ADAPTER_INFO);
	PIP_ADAPTER_INFO Info;
	ZeroMemory(&Info, size);
	
	// 네트워크 인터페이스 정보 가져오기
	int result = GetAdaptersInfo(Info, &size);
	if (result == ERROR_BUFFER_OVERFLOW)
	{
		Info = (PIP_ADAPTER_INFO)malloc(size);
		GetAdaptersInfo(Info, &size);
	}
	
	// 네트워크 인터페이스 MAC 주소
	memcpy(m_MyMACAddress, Info->Address, 6);
	// 네트워크 인터페이스 IP 주소
	u_long ipaddr = inet_addr(Info->IpAddressList.IpAddress.String);
	memcpy(m_MyIPAddress, &ipaddr, 4);
	// 네트워크 인터페이스 Netmask
	u_long netmask = inet_addr(Info->IpAddressList.IpMask.String);
	memcpy(&m_Netmask, &netmask, 4);

	free(Info);
}

// ethernet Header 셋팅
void CARPSocket::SetEthHeader(u_char *out, u_char *srcmac, u_char *dstmac)
{
	u_int16_t ptype = htons(PROTOCOLTYPE::ARP);	//프로토콜 타입 ARP로 고정

	memcpy(out, dstmac, MACADDRESSLENGTH);						// 목적지 하드웨어 주소
	memcpy(out + MACADDRESSLENGTH, srcmac, MACADDRESSLENGTH);	// 송신지 하드웨어 주소
	memcpy(out + (MACADDRESSLENGTH * 2), &ptype, 2);			// 프로토콜 타입
}

// ARP Packet 셋팅
void CARPSocket::SetARPPacket(u_char *out, u_char *srcmac, u_char *srcip, u_char *dstmac, u_char *dstip)
{
	ARPPacket arppacket;
	memset(&arppacket, 0, sizeof(ARPPacket));
	int arplen = sizeof(ARPPacket);

	// arppacket 만들기
	arppacket.htype = htons(ARPHRD::ETHERNET);			// 하드웨어 타입
	arppacket.ptype = htons(PROTOCOLTYPE::IPV4);		// 프로토콜 타입
	arppacket.hlen = MACADDRESSLENGTH;					// 하드웨어 주소 길이
	arppacket.plen = IPV4ADDRESSLENGTH;					// 프로토콜 주소 길이
	arppacket.opcode = htons(ARPOPCODE::ARPREQUEST);	// ARP OPCODE
	memcpy(arppacket.shaddr, srcmac, MACADDRESSLENGTH);	// 송신지 하드웨어 주소 설정
	memcpy(arppacket.spaddr, srcip, IPV4ADDRESSLENGTH);	// 송신지 IP address 셋팅
	memcpy(arppacket.dhaddr, dstmac, MACADDRESSLENGTH);	// 목적지 하드웨어 주소 설정
	memcpy(arppacket.dpaddr, dstip, IPV4ADDRESSLENGTH);	// 목적지 ip address 셋팅

	// 패킷 셋팅
	memcpy(out, &arppacket, arplen);
}

// 패킷 보내기
int CARPSocket::SendPacket(u_long dstip)
{
	u_char ethframe[ARPPACKETSIZE];
	u_char dstmac[MACADDRESSLENGTH];
	memset(ethframe, 0, ARPPACKETSIZE);

	memset(dstmac, 0xff, MACADDRESSLENGTH);		// 브로드 캐스팅 주소
	// 이더넷 프레임 헤더 셋팅
	SetEthHeader(ethframe,
				 m_MyMACAddress,
				 dstmac);

	memset(dstmac, 0x00, MACADDRESSLENGTH);		// 빈 주소
	// ARP 패킷 셋팅
	SetARPPacket(ethframe + ETHERNETHEADERLENGTH,
				 m_MyMACAddress,
				 m_MyIPAddress,
				 dstmac,
				 (u_char *)(&dstip));

	// 패킷 보내기
	int ret = pcap_sendpacket(m_pCapHandler, (u_char*)&ethframe, ARPPACKETSIZE);
	return ret;
}

// 패킷 보내기
int CARPSocket::SendPacket(u_long srcip, u_long dstip)
{
	u_char ethframe[ARPPACKETSIZE];
	u_char dstmac[MACADDRESSLENGTH];
	memset(ethframe, 0, ARPPACKETSIZE);
	
	memset(dstmac, 0xff, MACADDRESSLENGTH);		// 브로드 캐스팅 주소
	// 이더넷 프레임 헤더 셋팅
	SetEthHeader(ethframe,
				 m_MyMACAddress,
				 dstmac);

	memset(dstmac, 0x00, MACADDRESSLENGTH);		// 빈 주소
	// ARP 패킷 셋팅
	SetARPPacket(ethframe + ETHERNETHEADERLENGTH,
				 m_MyMACAddress,
				 (u_char *)(&srcip),
				 dstmac,
				 (u_char *)(&dstip));

	// 패킷 보내기
	int ret = pcap_sendpacket(m_pCapHandler, (u_char*)&ethframe, ARPPACKETSIZE);
	return ret;
}

// 패킷 캡쳐
void CARPSocket::StartCapture(int pckcnt)
{
	// 결과 비우기
	m_LHCapturedPacket.clear();

	// Winpcap ARP 필터 셋팅
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
		throw std::exception("너무 큰 인덱스");
	std::list<ARPPacket>::iterator li = m_LHCapturedPacket.begin();
	for (int i = 0; i < index; li++, i++);
	return *li;
}
