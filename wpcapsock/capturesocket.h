// �������� Ÿ�� ����
// 
#ifndef _CAPTURESOCKET_H__
#define _CAPTURESOCKET_H__

#include "inetproto.h"
#include "socket.h"

#define CAPTURESOCK_FILTERSTRING 

typedef void(*capture_handler)(const u_char *, const u_char *);

struct PCapLoopParam
{
	bool *param_stop;
	pcap_t *param_pcaphandle;
};

class CWPcapCaptureSocket : public CWPcapSocket
{
#ifdef _DEBUG
public:
#else // _DEBUG
protected:
#endif // _DEBUG
	// winpcap ��Ŷ ĸ�� ����
	char *m_pPacketFilter;
	// winpcap ���α׷��� ����
	struct bpf_program m_FilterCode;

	bool m_IsCapture;

public:
	static void PrintPacket(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
	void CreatePacketFilter(const char* filter = NULL);
	void StartCapture(pcap_handler handler, int pckcnt = 0);
	void StartCapture(capture_handler handler, u_char *param, int timeout, int pckcnt);
	void EndCapture();

public:
	CWPcapCaptureSocket();
	virtual ~CWPcapCaptureSocket();
};

#endif	// _CAPTURESOCKET_H__ //