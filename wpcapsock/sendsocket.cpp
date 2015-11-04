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

// ARP Table�� ARP�� ����Ͽ� ��� ���ּ� ����
int CWPcapSendSocket::SetETHHeaderWithARP(uint8_t *packet, uint8_t *src, uint16_t prototype, uint32_t dstip)
{
	// ARP ���̺� �ҷ�����
	PMIB_IPNETTABLE pMib = NULL;
	GetARPTable(&pMib);
	//for (int i = 0; i < pMib->dwNumEntries; i++)
	//{

	//}

	// ���� ��Ʈ��ũ���� Ȯ��
	// ������ ��� ARP ���̺� Ȯ��
	if (1)
	{
		// ���̺��� IP ã�ƺ���

		// ������ ���
		if (1)
		{

		}
		// ������ ARP ��û
		else
		{

		}

		// ARP ���� ������ �ش� ���ּ� ����
		if (1)
		{

		}
		// ARP ���� ������ ���� ���ϰ� ����
		else
		{
			return -1;
		}
	}
	// �ܺ��� ��� ARP ���̺��� ����Ʈ���� ���ּ� ��������
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

	// arppacket �����
	arppacket.htype = htons(ARPHRD::ETHERNET);			// �ϵ���� Ÿ��
	arppacket.ptype = htons(ETHTYPE::IPV4);		// �������� Ÿ��
	arppacket.hlen = MACADDRESS_LENGTH;					// �ϵ���� �ּ� ����
	arppacket.plen = IPV4ADDRESS_LENGTH;					// �������� �ּ� ����
	arppacket.opcode = op;	// ARP OPCODE
	memcpy(arppacket.shaddr, srcmac, MACADDRESS_LENGTH);	// �۽��� �ϵ���� �ּ� ����
	memcpy(arppacket.spaddr, srcip, IPV4ADDRESS_LENGTH);	// �۽��� IP address ����
	memcpy(arppacket.dhaddr, dstmac, MACADDRESS_LENGTH);	// ������ �ϵ���� �ּ� ����
	memcpy(arppacket.dpaddr, dstip, IPV4ADDRESS_LENGTH);	// ������ ip address ����

	// ��Ŷ ����
	memcpy(out, &arppacket, arplen);
}

int CWPcapSendSocket::SendARPRequest(uint32_t dstip)
{
	NICInfo *NICInfo = m_NICInfoList.At(m_CurSel);
	uint8_t ethframe[ARPMESSAGE_LENGTH];
	uint8_t dstmac[MACADDRESS_LENGTH];
	memset(ethframe, 0, ARPMESSAGE_LENGTH);

	// ��ε� ĳ���� �ּ� ����
	memset(dstmac, 0xff, MACADDRESS_LENGTH);
	// �̴��� ������ ��� ����
	SetETHHeader(ethframe, dstmac, NICInfo->NICMACAddress, htons(ETHTYPE::ARP));
	// �� �ּ� ����
	memset(dstmac, 0x00, MACADDRESS_LENGTH);
	// ARP ��Ŷ ����
	SetARPRequest(ethframe + ETHERNETHEADER_LENGTH,
		NICInfo->NICMACAddress,
		(uint8_t*)&NICInfo->NICIPAddress,
		dstmac,
		(uint8_t *)(&dstip),
		htons(ARPOPCODE::ARPREQUEST));

	// ��Ŷ ������
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

// ip ����ȭ ����

// ip ���� ����
// �÷��� ���� �� 
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

	// ICMP ��� ����

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

	// IP ��� ����(-����ȭ ��� x-)
	uint8_t *pip = packet + ethlen;
	datalen += ICMPV4HEADER_LENGTH;
	SetIPPacket(pip, IPV4HEADER_BASICLENGTH, rand() %0x10000, 0x0000, IPV4TYPE::ICMP, (uint8_t *)&nicinfo->NICIPAddress, (uint8_t *)&dstip, (uint8_t *)picmp, datalen);

	// �̴��� ��� ���� ����(���� ����!!! - �̴��� ��� ���ÿ��� �� �־���� ����)
	// ARP ���̺� �ҷ�����
	PMIB_IPNETTABLE pMib = NULL;
	GetARPTable(&pMib);
	for (int i = 0; i < pMib->dwNumEntries; i++)
	{

	}
	

	// ��Ʈ��ũ ���� / �ܺ� Ȯ��
	uint32_t maclen = MACADDRESS_LENGTH;
	uint8_t mac[MACADDRESS_LENGTH];
	memset(mac, 0, MACADDRESS_LENGTH);

	if (IsInNet(dstip))		// ���� ��Ʈ��ũ�� ��� ARP ����
	{
		GetDstMAC(mac, dstip);
	}
	else
	{
		// �ܺ� ��Ʈ��ũ�� ��� ARP ���̺��� ����Ʈ���� �ּ� ��������
	}

	// ������ ���� arp ����
	// SendARP((IPAddr)dstip, nicinfo->NICIPAddress, nicinfo->NICMACAddress, (PULONG)&maclen);
	// ���� ���� ARP ������Ʈ
	SendARPRequest((IPAddr)dstip);

	// �̴��� ��� ����
	SetETHHeader(packet, mac, nicinfo->NICMACAddress, htons(ETHTYPE::IPV4));

	// ��Ŷ ����
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