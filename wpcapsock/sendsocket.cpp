#include "sendsocket.h"

CWPcapSendSocket::CWPcapSendSocket() : CWPcapSocket()
{

}
CWPcapSendSocket::~CWPcapSendSocket()
{
}

int CWPcapSendSocket::SendPacket(uint8_t *packet, int len)
{
	int ret = pcap_sendpacket(m_pCapHandler, packet, len);
	return ret;
}

// 이더넷 헤더 셋팅
// ARP Table과 ARP를 사용하여 상대 맥주소 설정
// @packet: 셋팅할 버퍼 위치
// @src: 메시지 송신자 맥 주소
// @prototype: 프로토콜 타입
// @dstip: 목적지 ip 주소
int CWPcapSendSocket::SetETHHeaderWithARP(uint8_t *packet, uint8_t *src, uint16_t prototype, uint32_t dstip)
{
	// ARP 테이블 불러오기
	PMIB_IPNETTABLE pMib = NULL;
	GetARPTable(&pMib);

	uint8_t dstmac[MACADDRESS_LENGTH];
	memset(dstmac, 0, MACADDRESS_LENGTH);

	// 내부 네트워크인지 확인
	DWORD i = 0;
	if (IsInNet(dstip))		
	{
		// 내부일 경우 ARP 테이블 확인
		for (; i < pMib->dwNumEntries; i++)
		{
			if (pMib->table[i].dwAddr == dstip)
			{
				memcpy(dstmac, pMib->table[i].bPhysAddr, pMib->table[i].dwPhysAddrLen);
				break;
			}
		}
		// ARP 테이블에 있으면 해당 맥주소 셋팅
		if (i < pMib->dwNumEntries)
			SetETHHeader(packet, dstmac, m_NICInfoList.At(m_CurSel)->NICMACAddress, prototype);
		// 없으면 ARP 요청
		else
		{
			// ARP 응답 없으면 셋팅 안하고 종료
			if (GetDstMAC(dstmac, dstip, 1000) == -1)
				goto error;
			else
				SetETHHeader(packet, dstmac, m_NICInfoList.At(m_CurSel)->NICMACAddress, prototype);
		}
		goto end;
	}// 외부일 경우 ARP 테이블에서 게이트웨이 맥주소 가져온다
	else
	{
		// 게이트웨이 맥주소 확인
		for (; i < pMib->dwNumEntries; i++)
		{
			if (pMib->table[i].dwAddr == m_NICInfoList.At(m_CurSel)->GatewayIPAddress)
			{
				memcpy(dstmac, pMib->table[i].bPhysAddr, pMib->table[i].dwPhysAddrLen);
				SetETHHeader(packet, dstmac, m_NICInfoList.At(m_CurSel)->NICMACAddress, prototype);
				goto end;
			}
		}
		goto error;
	}

// 정상 종료
end:
	free(pMib);
	return 0;

// ARP 응답 없음
error:
	free(pMib);
	return -1;
}

void CWPcapSendSocket::SetETHHeader(uint8_t *packet, uint8_t *dst, uint8_t *src, uint16_t prototype)
{
	memcpy(packet, dst, MACADDRESS_LENGTH);
	memcpy(packet + MACADDRESS_LENGTH, src, MACADDRESS_LENGTH);
	memcpy(packet + MACADDRESS_LENGTH * 2, &prototype, 2);
}

void CWPcapSendSocket::SetARPRequest(uint8_t *out, uint8_t *srcmac, uint8_t *srcip, uint8_t *dstmac, uint8_t *dstip, uint16_t op)
{
	ARPPacket arppacket;
	memset(&arppacket, 0, sizeof(ARPPacket));
	int arplen = sizeof(ARPPacket);

	// arppacket 만들기
	arppacket.htype = htons(ARPHRD::ETHERNET);			// 하드웨어 타입
	arppacket.ptype = htons(ETHTYPE::IPV4);				// 프로토콜 타입
	arppacket.hlen = MACADDRESS_LENGTH;					// 하드웨어 주소 길이
	arppacket.plen = IPV4ADDRESS_LENGTH;					// 프로토콜 주소 길이
	arppacket.opcode = op;	// ARP OPCODE
	memcpy(arppacket.shaddr, srcmac, MACADDRESS_LENGTH);	// 송신지 하드웨어 주소 설정
	memcpy(arppacket.spaddr, srcip, IPV4ADDRESS_LENGTH);	// 송신지 IP address 셋팅
	memcpy(arppacket.dhaddr, dstmac, MACADDRESS_LENGTH);	// 목적지 하드웨어 주소 설정
	memcpy(arppacket.dpaddr, dstip, IPV4ADDRESS_LENGTH);	// 목적지 ip address 셋팅

	// 패킷 셋팅
	memcpy(out, &arppacket, arplen);
}
int CWPcapSendSocket::SendARPRequest(uint32_t dstip)
{
	NICInfo *NICInfo = m_NICInfoList.At(m_CurSel);
	uint8_t ethframe[ARPMESSAGE_LENGTH];
	uint8_t dstmac[MACADDRESS_LENGTH];
	memset(ethframe, 0, ARPMESSAGE_LENGTH);

	// 브로드 캐스팅 주소 셋팅
	memset(dstmac, 0xff, MACADDRESS_LENGTH);
	// 이더넷 프레임 헤더 셋팅
	SetETHHeader(ethframe, dstmac, NICInfo->NICMACAddress, htons(ETHTYPE::ARP));
	// 빈 주소 셋팅
	memset(dstmac, 0x00, MACADDRESS_LENGTH);
	// ARP 패킷 셋팅
	SetARPRequest(ethframe + ETHERNETHEADER_LENGTH,
		NICInfo->NICMACAddress,
		(uint8_t*)&NICInfo->NICIPAddress,
		dstmac,
		(uint8_t *)(&dstip),
		htons(ARPOPCODE::ARPREQUEST));

	// 패킷 보내기
	int ret = pcap_sendpacket(m_pCapHandler, (u_char*)&ethframe, ARPMESSAGE_LENGTH);

	return ret;
}
int CWPcapSendSocket::GetDstMAC(uint8_t *dstmac, uint32_t dstip, uint32_t timeout)
{
	ARPPacket *arpp;
	pcap_pkthdr pkthdr;
	uint8_t *packet = NULL;
	SYSTEMTIME systime;

	// ARP 필터 셋팅
	bpf_program filter;
	pcap_compile(m_pCapHandler, &filter, "arp", 1, m_NICInfoList.At(m_CurSel)->Netmask);
	pcap_setfilter(m_pCapHandler, &filter);

	// timeout 확인용 변수
	GetSystemTime(&systime);
	uint32_t starttime = systime.wMilliseconds + systime.wSecond * 1000;
	uint32_t endtime;

	// ARP 요청을 보낸 뒤 확인
	for (int n = 0; n < 5; n++)
	{
		// ARP 요청
		SendARPRequest(dstip);
		// 패킷 확인, 100개정도 확인하고 다시 시도
		for (int i = 0; i < 200; i++)
		{
			// timeout 확인
			GetSystemTime(&systime);
			endtime = systime.wMilliseconds + systime.wSecond * 1000;
			if (endtime - starttime > timeout)
				return -1;
			// 응답 패킷 확인
			packet = (uint8_t*)pcap_next(m_pCapHandler, &pkthdr);
			if (packet == NULL)
				continue;
			uint16_t op;
			memcpy(&op, packet + MACADDRESS_LENGTH * 2, 2);
			if (op == htons(ETHTYPE::ARP))
			{
				arpp = (ARPPacket*)(packet + ETHERNETHEADER_LENGTH);
				uint32_t ip;
				memcpy(&ip, &arpp->spaddr, IPV4ADDRESS_LENGTH);
				if (ip == dstip)
				{
					memcpy(dstmac, (arpp->shaddr), MACADDRESS_LENGTH);
					return 0;
				}
			}
		}
	}
	// 필터 해제
	pcap_freecode(&filter);
	return -1;
}

// ip 직접 셋팅
// 플래그 셋팅 시 
void CWPcapSendSocket::SetIPPacket(
	uint8_t *packet,
	uint16_t headerlen,
	uint16_t identification,
	uint16_t flags,
	uint8_t ttl,
	uint8_t prototype,
	bool ischeck,
	uint8_t *srcip,
	uint8_t *dstip,
	uint8_t *data,
	uint16_t datalen,
	uint8_t *option,
	uint16_t)
{
	IPV4Header *piph = (IPV4Header*)packet;
	piph->version = 4;
	piph->headerlen = headerlen / 4;
	piph->tos = 0;
	piph->totallen = htons(headerlen + datalen);
	
	piph->identification = identification;
	piph->flags = flags;

	piph->ttl = ttl;
	piph->protoid = prototype;
	piph->checksum = 0;
	memcpy(piph->srcaddr, srcip, IPV4ADDRESS_LENGTH);
	memcpy(piph->dstaddr, dstip, IPV4ADDRESS_LENGTH);

	if (ischeck)
	{
		
		piph->checksum = IPHeaderChecksum(headerlen, (uint8_t*)piph);
		piph->checksum = htons(piph->checksum);
	}
}


int CWPcapSendSocket::GetARPTable(PMIB_IPNETTABLE *pmib)
{
	ULONG nSize = 0;
	DWORD dwRet = GetIpNetTable(*pmib, &nSize, TRUE);
	if (dwRet == ERROR_INSUFFICIENT_BUFFER)
	{
		*pmib = (PMIB_IPNETTABLE)malloc(sizeof(MIB_IPNETTABLE) + sizeof(MIB_IPNETROW)*nSize);
		memset(*pmib, 0, nSize);
		GetIpNetTable(*pmib, &nSize, TRUE);
	}
	else
	{
		return -1;
	}

	return 0;
}

int CWPcapSendSocket::SendICMPV4ECHORequest(uint32_t dstip)
{
	NICInfo *nicinfo = m_NICInfoList.At(m_CurSel);
	uint16_t packetlen = ICMPV4ECHO_LENGTH + IPV4HEADER_BASICLENGTH + ETHERNETHEADER_LENGTH;
	uint8_t *packet = (uint8_t *)malloc(packetlen);
	memset(packet, 0, packetlen);

	// ICMP 헤더 셋팅
	uint8_t *picmp = (packet + IPV4HEADER_BASICLENGTH + ETHERNETHEADER_LENGTH);
	uint16_t datalen = ICMPV4ECHO_LENGTH - ICMPV4HEADER_LENGTH;
	uint8_t *data = (uint8_t *)malloc(datalen);
	uint16_t i = 0;
	memset(data, 0, datalen);
	for (int i = 0; i < datalen; i++)
		data[i] = i + 0x60;
	SetICMPV4Packet(picmp, ICMPV4TYPE::ICMPV4_ECHO_REQUEST,	0, rand()%0x10000, 0x0000, data, datalen);
	free(data);

	// IP 헤더 셋팅
	uint8_t *pip = packet + ETHERNETHEADER_LENGTH;
	datalen += ICMPV4HEADER_LENGTH;
	SetIPPacket(pip, IPV4HEADER_BASICLENGTH, 0x3713, 0x0000,
		128, IPV4TYPE::ICMP, true, (uint8_t *)&nicinfo->NICIPAddress,
		(uint8_t *)&dstip, (uint8_t *)picmp, datalen);

	// 이더넷 헤더 셋팅
	SetETHHeaderWithARP(packet, nicinfo->NICMACAddress, htons(ETHTYPE::IPV4), dstip);

	// 패킷 전송
	int ret = SendPacket(packet, packetlen);
	free(packet);
	return ret;
}

void CWPcapSendSocket::SetICMPV4Packet(uint8_t *out, uint8_t type, uint8_t code, uint16_t iden, uint16_t seq, uint8_t *data, uint16_t datalen)
{
	ICMPV4Header *icmph = (ICMPV4Header *)out;
	uint16_t len = ICMPV4HEADER_LENGTH + datalen;
	icmph->type = type;
	icmph->code = code;
	icmph->checksum = 0;
	icmph->identifier = iden;
	icmph->seqnum = seq;
	memcpy(out + ICMPV4HEADER_LENGTH, data, datalen);
	icmph->checksum = ICMPV4HeaderChecksum(len, (uint8_t*)out);
	icmph->checksum = htons(icmph->checksum);
}

bool CWPcapSendSocket::IsInNet(uint32_t ip)
{
	NICInfo *NICInfo = m_NICInfoList.At(m_CurSel);
	uint32_t netmask = NICInfo->Netmask;
	uint32_t nicip = NICInfo->NICIPAddress;
	uint32_t net = nicip & netmask;

	ip = ntohl(ip);
	if (ip > ntohl(net) && ip < ntohl(net + ~netmask))
		return true;
	else
		return false;
}

int CWPcapSendSocket::SendUDP()
{
	NICInfo *nicinfo = m_NICInfoList.At(m_CurSel);
	uint16_t packetlen = UDPHEADER_LENGTH + IPV4HEADER_BASICLENGTH + ETHERNETHEADER_LENGTH;
	uint16_t udplen = UDPHEADER_LENGTH;
	uint16_t ipheaderlen = IPV4HEADER_BASICLENGTH;
	uint16_t ethlen = ETHERNETHEADER_LENGTH;
	uint8_t *packet = (uint8_t *)malloc(packetlen);
	memset(packet, 0, packetlen);

	uint8_t *pudp = (packet + ipheaderlen + ethlen);
	uint16_t datalen = udplen - ICMPV4HEADER_LENGTH;
	uint8_t *data = (uint8_t *)malloc(datalen);
	uint16_t i = 0;

	// UDP 데이터 셋팅
	memset(data, 0, datalen);
	for (int i = 0; i < datalen; i++)
		data[i] = i + 0x44;

	uint32_t dstip = inet_addr("172.16.5.201");
	SetUDP(packet, nicinfo->NICIPAddress, dstip, 1300, 1300, data, datalen);
	free(data);

	// IP 헤더 셋팅(-단편화 고려 x-)
	uint8_t *pip = packet + ethlen;
	datalen += ICMPV4HEADER_LENGTH;
	SetIPPacket(
		pip,
		IPV4HEADER_BASICLENGTH,
		0x3713,
		0x0000,
		128,
		IPV4TYPE::UDP,
		true,
		(uint8_t *)&nicinfo->NICIPAddress,
		(uint8_t *)&dstip,
		(uint8_t *)pudp,
		datalen);

	// 이더넷 헤더 셋팅
	SetETHHeaderWithARP(packet, nicinfo->NICMACAddress, htons(ETHTYPE::IPV4), dstip);
	// 패킷 전송
	int ret = SendPacket(packet, packetlen);
	return ret;
}

void CWPcapSendSocket::SetUDP(uint8_t* packet, uint32_t srcip, uint32_t dstip, uint16_t srcport, uint16_t dstport, uint8_t *data, uint16_t datalen)
{
	USHORT TotalLen = datalen + 20 + 8;
	//Beginning of UDP Header
	uint16_t TmpType;
	
	TmpType = htons(srcport);
	memcpy((void*)(packet + 34), (void*)&TmpType, 2);
	TmpType = htons(dstport);
	memcpy((void*)(packet + 36), (void*)&TmpType, 2);
	USHORT UDPTotalLen = htons(datalen + 8); // UDP Length does not include length of IP header
	memcpy((void*)(packet + 38), (void*)&UDPTotalLen, 2);
	//memcpy((void*)(FinalPacket+40),(void*)&TmpType,2); //checksum
	memcpy((void*)(packet + 42), (void*)data, datalen);

	unsigned short UDPChecksum = CalculateUDPChecksum(packet, data, datalen, srcip, dstip, htons(srcport), htons(dstport), 0x11);
	memcpy((void*)(packet + 40), (void*)&UDPChecksum, 2);
}

uint16_t CWPcapSendSocket::BytesTo16(unsigned char X, unsigned char Y)
{
	unsigned short Tmp = X;
	Tmp = Tmp << 8;
	Tmp = Tmp | Y;
	return Tmp;
}

uint16_t CWPcapSendSocket::CalculateUDPChecksum(uint8_t *packet, unsigned char* UserData, int UserDataLen, UINT SourceIP, UINT DestIP, USHORT SourcePort, USHORT DestinationPort, UCHAR Protocol)
{
	unsigned short CheckSum = 0;
	unsigned short PseudoLength = UserDataLen + 8 + 9; //Length of PseudoHeader = Data Length + 8 bytes UDP header (2Bytes Length,2 Bytes Dst Port, 2 Bytes Src Port, 2 Bytes Checksum)
	//+ Two 4 byte IP's + 1 byte protocol
	PseudoLength += PseudoLength % 2; //If bytes are not an even number, add an extra.
	unsigned short Length = UserDataLen + 8; // This is just UDP + Data length. needed for actual data in udp header

	unsigned char* PseudoHeader = new unsigned char[PseudoLength];
	for (int i = 0; i < PseudoLength; i++){ PseudoHeader[i] = 0x00; }

	PseudoHeader[0] = 0x11;

	memcpy((void*)(PseudoHeader + 1), (void*)(packet + 26), 8); // Source and Dest IP

	Length = htons(Length);
	memcpy((void*)(PseudoHeader + 9), (void*)&Length, 2);
	memcpy((void*)(PseudoHeader + 11), (void*)&Length, 2);

	memcpy((void*)(PseudoHeader + 13), (void*)(packet + 34), 2);
	memcpy((void*)(PseudoHeader + 15), (void*)(packet + 36), 2);

	memcpy((void*)(PseudoHeader + 17), (void*)UserData, UserDataLen);


	for (int i = 0; i < PseudoLength; i += 2)
	{
		unsigned short Tmp = BytesTo16(PseudoHeader[i], PseudoHeader[i + 1]);
		unsigned short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference){ CheckSum += 1; }
	}
	CheckSum = ~CheckSum; //One's complement
	return CheckSum;
}