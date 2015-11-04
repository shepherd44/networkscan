#include "capturesocket.h"

CWPcapCaptureSocket::CWPcapCaptureSocket() : CWPcapSocket()
{
	m_IsCapture = false;
	memset(&m_FilterCode, 0, sizeof(bpf_program));
	m_FilterCode.bf_len = -1;
}
CWPcapCaptureSocket::~CWPcapCaptureSocket()
{

}

void CWPcapCaptureSocket::CreatePacketFilter(const char* filter)
{
	pcap_compile(m_pCapHandler, &m_FilterCode, filter, 1, m_NICInfoList.At(m_CurSel)->Netmask);
}

// pcap_loop 버전
void CWPcapCaptureSocket::StartCapture(pcap_handler handler, int pckcnt)
{
	static struct PCapLoopParam param;
	m_IsCapture = true;
	pcap_setfilter(m_pCapHandler, &m_FilterCode);
	param.param_stop = &m_IsCapture;
	param.param_pcaphandle = m_pCapHandler;
	pcap_loop(m_pCapHandler, pckcnt, CWPcapCaptureSocket::PrintPacket, (u_char *)&param);
}

// pcap_next 무한 루프 버전
void CWPcapCaptureSocket::StartCapture(capture_handler handler, uint8_t *param, int timeout, int pckcnt)
{
	struct pcap_pkthdr pkthdr;
	u_char* packet;
	m_IsCapture = true;
	while (1)
	{	
		packet = (u_char *)pcap_next(m_pCapHandler, &pkthdr);
		// 패킷 처리 콜백 함수 실행
		if (handler != NULL && packet != NULL)
			handler(param, packet);
		
		if (!m_IsCapture)
			break;
	}
	return;
}

void CWPcapCaptureSocket::EndCapture()
{
	m_IsCapture = false;
	if (m_FilterCode.bf_len != -1)
		pcap_freecode(&m_FilterCode);
}

void CWPcapCaptureSocket::PrintPacket(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct PCapLoopParam *capparam = (struct PCapLoopParam *)param;
	if (*capparam->param_stop)
		pcap_breakloop(capparam->param_pcaphandle);
	ETHHeader *ethh = (ETHHeader *)pkt_data;
	PIPV4Header iph;
	printf("-------------------------------------------\n");
	printf("dstMAC: %02X:%02X:%02X:%02X:%02X:%02X:\n", ethh->dstmac[0], ethh->dstmac[1], ethh->dstmac[2],
													   ethh->dstmac[3], ethh->dstmac[4], ethh->dstmac[5]);
	printf("srcMAC: %02X:%02X:%02X:%02X:%02X:%02X:\n", ethh->srcmac[0], ethh->srcmac[1], ethh->srcmac[2],
													   ethh->srcmac[3], ethh->srcmac[4], ethh->srcmac[5]);

	
	switch (ntohs(ethh->prototype))
	{
	case ETHTYPE::ARP:
		printf("protocol type: ARP\n");
		break;
	case ETHTYPE::IPV4:
		iph = (PIPV4Header)(pkt_data + ETHERNETHEADER_LENGTH);
		printf("protocol type: IPV4\n");
		printf("srcIP: %d.%d.%d.%d\n", iph->srcaddr[0], iph->srcaddr[1], iph->srcaddr[2], iph->srcaddr[3]);
		printf("dstIP: %d.%d.%d.%d\n", iph->dstaddr[0], iph->dstaddr[1], iph->dstaddr[2], iph->dstaddr[3]);
		switch (iph->protoid)
		{
		case IPV4TYPE::ICMP:
			printf("ProtocolType: ICMP\n");
			break;
		case IPV4TYPE::TCP:
			printf("ProtocolType: TCP\n");
			break;
		case IPV4TYPE::UDP:
			printf("ProtocolType: UDP\n");
			break;
		default:
			break;
		}
		
		break;
	default:
		printf("protocol type: OTHER\n");
		break;
	}
	
}