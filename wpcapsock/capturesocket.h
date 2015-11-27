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
protected:
	// winpcap ��Ŷ ĸ�� ����
	//char *m_pPacketFilter;
	// winpcap ���α׷��� ����
	//struct bpf_program m_FilterCode;

	bool m_IsCapturing;

public:
	// ĸó ���� ����
	// ������ ���� ���� �ڵ� �����ϵ��� ���� �ʿ�
	int SetPacketFilter(const char* filter = NULL);
	// pcap_loop ����
	void StartCapture(pcap_handler handler, int pckcnt = 0);
	// pcap_next�� ����(�� �� timeout�� ��Ŷ ���� ó��)
	void StartCapture(capture_handler callback, u_char *param, int timeout, int pckcnt);
	// ĸ�� ����
	void EndCapture();

	// ��Ŷ ��� �Լ�(�ڵ鷯 ������)
	static void PrintPacket(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
public:
	CWPcapCaptureSocket();
	virtual ~CWPcapCaptureSocket();
};

#endif	// _CAPTURESOCKET_H__ //