// 프로토콜 타입 정의
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
	// winpcap 패킷 캡쳐 필터
	//char *m_pPacketFilter;
	// winpcap 프로그램된 필터
	//struct bpf_program m_FilterCode;

	bool m_IsCapturing;

public:
	// 캡처 필터 설정
	// 설정에 따른 필터 자동 생성하도록 수정 필요
	int SetPacketFilter(const char* filter = NULL);
	// pcap_loop 버전
	void StartCapture(pcap_handler handler, int pckcnt = 0);
	// pcap_next로 구현(추 후 timeout과 패킷 갯수 처리)
	void StartCapture(capture_handler callback, u_char *param, int timeout, int pckcnt);
	// 캡쳐 종료
	void EndCapture();

	// 패킷 출력 함수(핸들러 예제용)
	static void PrintPacket(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
public:
	CWPcapCaptureSocket();
	virtual ~CWPcapCaptureSocket();
};

#endif	// _CAPTURESOCKET_H__ //