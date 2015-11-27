#include "capturesocket.h"

CWPcapCaptureSocket::CWPcapCaptureSocket() : CWPcapSocket()
{
	m_IsCapturing = false;
}
CWPcapCaptureSocket::~CWPcapCaptureSocket()
{

}

int CWPcapCaptureSocket::SetPacketFilter(const char* filter)
{
	struct bpf_program filtercode;
	if (pcap_compile(m_pCapHandler, &filtercode, filter, 1, 0xffffffff) < 0)
	{
		strcpy(m_ErrBuffer, pcap_geterr(m_pCapHandler));
		throw WPcapSocketException(m_ErrBuffer);
	}
	
	if (pcap_setfilter(m_pCapHandler, &filtercode) < 0)
		return -1;
	pcap_freecode(&filtercode);
	return 0;
}

// pcap_loop 버전
void CWPcapCaptureSocket::StartCapture(pcap_handler handler, int pckcnt)
{
	struct PCapLoopParam param;
	m_IsCapturing = true;
	param.param_stop = &m_IsCapturing;
	param.param_pcaphandle = m_pCapHandler;
	pcap_loop(m_pCapHandler, pckcnt, CWPcapCaptureSocket::PrintPacket, (u_char *)&param);
}

void CWPcapCaptureSocket::StartCapture(capture_handler callback, uint8_t *param, int timeout, int pckcnt)
{
	struct pcap_pkthdr pkthdr;
	u_char* packet;
	m_IsCapturing = true;
	while (m_IsCapturing)
	{	
		packet = NULL;
		packet = (u_char *)pcap_next(m_pCapHandler, &pkthdr);
		// 패킷 처리 콜백 함수 실행
		if (callback != NULL && packet != NULL)
			callback(param, packet);
	}
	return;
}

void CWPcapCaptureSocket::EndCapture()
{
	m_IsCapturing = false;
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