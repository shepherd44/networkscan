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

// ARP Table과 ARP를 사용하여 상대 맥주소 설정
int CWPcapSendSocket::SetETHHeaderWithARP(uint8_t *packet, uint8_t *src, uint16_t prototype, uint32_t dstip)
{
	// ARP 테이블 불러오기
	PMIB_IPNETTABLE pMib = NULL;
	GetARPTable(&pMib);
	//for (int i = 0; i < pMib->dwNumEntries; i++)
	//{

	//}

	// 내부 네트워크인지 확인
	// 내부일 경우 ARP 테이블 확인
	if (1)
	{
		// 테이블에서 IP 찾아보기

		// 있으면 사용
		if (1)
		{

		}
		// 없으면 ARP 요청
		else
		{

		}

		// ARP 응답 있으면 해당 맥주소 셋팅
		if (1)
		{

		}
		// ARP 응답 없으면 셋팅 안하고 종료
		else
		{
			return -1;
		}
	}
	// 외부일 경우 ARP 테이블에서 게이트웨이 맥주소 가져오기
	else
	{

	}
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


int CWPcapSendSocket::GetDstMAC(uint8_t *dstmac, uint32_t dstip)
{
	ARPPacket *arpp;
	pcap_pkthdr pkthdr;
	uint8_t *packet;

	SendARPRequest(dstip);
	SendARPRequest(dstip);
	SendARPRequest(dstip);
	for (int i = 0; i < 100; i++)
	{
		packet = (uint8_t*)pcap_next(m_pCapHandler, &pkthdr);
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
	return -1;
}

// ip 단편화 전송

// ip 직접 셋팅
// 플래그 셋팅 시 
void CWPcapSendSocket::SetIPPacket(
	uint8_t *packet,
	uint16_t headerlen,
	uint16_t identification,
	uint16_t flags,
	uint8_t prototype,
	uint8_t *srcip,
	uint8_t *dstip,
	uint8_t *data,
	uint16_t datalen)
{
	IPV4Header *piph = (IPV4Header*)packet;
	piph->version = 4;
	piph->headerlen = headerlen / 4;
	piph->tos = 0;
	piph->totallen = htons(headerlen + datalen);
	
	piph->identification = identification;
	piph->flags = flags;

	piph->ttl = 128;
	piph->protoid = prototype;
	piph->checksum = 0;
	memcpy(piph->srcaddr, srcip, IPV4ADDRESS_LENGTH);
	memcpy(piph->dstaddr, dstip, IPV4ADDRESS_LENGTH);

	piph->checksum = IPHeaderChecksum(piph->headerlen, (uint16_t*)piph);
	piph->checksum = htons(piph->checksum);
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

void CWPcapSendSocket::SendICMPV4ECHORequest(uint32_t dstip)
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
	for (; i < datalen - 9; i++)
		data[i] = i + 0x61;
	for (; i < datalen; i++)
		data[i] = i + 0x4a;


	SetICMPV4Packet(picmp, ICMPV4TYPE::ICMPV4_ECHO_REQUEST,	0, 0x0100, 0x0100, data, datalen);
	free(data);

	// IP 헤더 셋팅(-단편화 고려 x-)
	uint8_t *pip = packet + ethlen;
	datalen += ICMPV4HEADER_LENGTH;
	SetIPPacket(pip, IPV4HEADER_BASICLENGTH, rand() %0x10000, 0x0000, IPV4TYPE::ICMP, (uint8_t *)&nicinfo->NICIPAddress, (uint8_t *)&dstip, (uint8_t *)picmp, datalen);

	// 이더넷 헤더 셋팅 과정(따로 뺄것!!! - 이더넷 헤더 셋팅에서 해 주어야할 과정)
	// ARP 테이블 불러오기
	PMIB_IPNETTABLE pMib = NULL;
	GetARPTable(&pMib);
	for (int i = 0; i < pMib->dwNumEntries; i++)
	{

	}
	

	// 네트워크 내부 / 외부 확인
	uint32_t maclen = MACADDRESS_LENGTH;
	uint8_t mac[MACADDRESS_LENGTH];
	memset(mac, 0, MACADDRESS_LENGTH);

	if (IsInNet(dstip))		// 내부 네트워크일 경우 ARP 전송
	{
		GetDstMAC(mac, dstip);
	}
	else
	{
		// 외부 네트워크일 경우 ARP 테이블에서 게이트웨이 주소 가져오기
	}

	// 윈도우 버전 arp 전송
	// SendARP((IPAddr)dstip, nicinfo->NICIPAddress, nicinfo->NICMACAddress, (PULONG)&maclen);
	// 내가 만든 ARP 리퀘스트
	SendARPRequest((IPAddr)dstip);

	// 이더넷 헤더 셋팅
	SetETHHeader(packet, mac, nicinfo->NICMACAddress, htons(ETHTYPE::IPV4));

	// 패킷 전송
	SendPacket(packet, packetlen);
	free(pMib);
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

	if (ip > net && ip < net + ~netmask)
		return true;
	else
		return false;
}