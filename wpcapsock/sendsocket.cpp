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

	uint32_t maclen = MACADDRESS_LENGTH;
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
		// ARP 응답 있으면 해당 맥주소 셋팅
		if (i < pMib->dwNumEntries)
		{
			SetETHHeader(packet, dstmac, m_NICInfoList.At(m_CurSel)->NICMACAddress, prototype);
		}// 없으면 ARP 요청
		else
		{
			if (GetDstMAC(dstmac, dstip, 1000))
			{
				return -1;
			}// ARP 응답 없으면 셋팅 안하고 종료
			else
			{
				SetETHHeader(packet, dstmac, m_NICInfoList.At(m_CurSel)->NICMACAddress, prototype);
			}
		}	
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
				return 0;
			}
		}
		return -1;
	}
	return 0;
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
	arppacket.ptype = htons(ETHTYPE::IPV4);		// 프로토콜 타입
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
		for (int i = 0; i < 100; i++)
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
		piph->checksum = IPHeaderChecksum(piph->headerlen, (uint16_t*)piph);
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

void CWPcapSendSocket::SendPingInWin(uint32_t dstip)
{
	HANDLE hIcmpFile;
	DWORD dwRetVal = 0;
	char SendData[32] = "Data Buffer";
	LPVOID ReplyBuffer = NULL;
	DWORD ReplySize = 0;

	hIcmpFile = IcmpCreateFile();
	if (hIcmpFile == INVALID_HANDLE_VALUE)
	return ;

	ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
	ReplyBuffer = (VOID*)malloc(ReplySize);
	if (ReplyBuffer == NULL)
	return ;

	dwRetVal = IcmpSendEcho(hIcmpFile, dstip, SendData, sizeof(SendData),
	NULL, ReplyBuffer, ReplySize, 100);

	//CloseHandle(hIcmpFile);
	free(ReplyBuffer);
}
int CWPcapSendSocket::SendICMPV4ECHORequest(uint32_t dstip)
{
	NICInfo *nicinfo = m_NICInfoList.At(m_CurSel);
	uint16_t packetlen = ICMPV4ECHO_LENGTH + IPV4HEADER_BASICLENGTH + ETHERNETHEADER_LENGTH;
	uint16_t icmpv4len = ICMPV4ECHO_LENGTH;
	uint16_t ipheaderlen = IPV4HEADER_BASICLENGTH;
	uint16_t ethlen = ETHERNETHEADER_LENGTH;
	uint8_t *packet = (uint8_t *)malloc(packetlen);
	memset(packet, 0, packetlen);

	// ICMP 헤더 셋팅
	uint8_t *picmp = (packet + ipheaderlen + ethlen);
	uint16_t datalen = icmpv4len - ICMPV4HEADER_LENGTH;
	uint8_t *data = (uint8_t *)malloc(datalen);
	uint16_t i = 0;
	
	memset(data, 0, datalen);
	data[0] = 0x44;
	data[1] = 0x61;
	data[2] = 0x74;
	data[3] = 0x61;
	data[4] = 0x20;
	data[5] = 0x42;
	data[6] = 0x75;
	data[7] = 0x66;
	data[8] = 0x66;
	data[9] = 0x65;

	SetICMPV4Packet(picmp, ICMPV4TYPE::ICMPV4_ECHO_REQUEST,	0, rand()%0x10000, 0x0000, data, datalen);
	free(data);

	// IP 헤더 셋팅(-단편화 고려 x-)
	uint8_t *pip = packet + ethlen;
	datalen += ICMPV4HEADER_LENGTH;
	SetIPPacket(
		pip,
		IPV4HEADER_BASICLENGTH,
		0xe92a,
		0x0000,
		255,
		IPV4TYPE::ICMP,
		false,
		(uint8_t *)&nicinfo->NICIPAddress,
		(uint8_t *)&dstip,
		(uint8_t *)picmp,
		datalen);

	// 이더넷 헤더 셋팅
	//SetETHHeader(packet, dstmac, nicinfo->NICMACAddress, htons(ETHTYPE::IPV4));
	SetETHHeaderWithARP(packet, nicinfo->NICMACAddress, htons(ETHTYPE::IPV4), dstip);
	// 패킷 전송
	int ret = SendPacket(packet, packetlen);
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
	icmph->checksum = ICMPV4HeaderChecksum(len, (uint16_t*)out);
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