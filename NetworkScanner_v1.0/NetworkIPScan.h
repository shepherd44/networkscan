#pragma once

#include "capturesocket.h"
#include "sendsocket.h"
#include "IPStatusList.h"


#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
	#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

// pcpa_pkthdr copy
// pcap ver:4.1.3
//struct pcap_pkthdr {
//	struct timeval ts;	/* time stamp */
//	bpf_u_int32 caplen;	/* length of portion present */
//	bpf_u_int32 len;	/* length this packet (off wire) */
//};

// 캡처 스레드 파라미터
// 파라미터 3개 구조체
struct ThreadParams
{
	void *socket;
	void *list;
	void *isend;
};

class CNetworkIPScan
{
private:
	// IP 상태 저장 리스트 헤더
	CIPStatusList m_IPStatInfoList;

	// Socket
	CWPcapSendSocket m_SendSock;		// 보내기 소켓 겸 NIC 정보
	CWPcapCaptureSocket m_CaptureSock;

	// 쓰레드 핸들
	CWinThread *m_hCaptureThread;
	CWinThread *m_hSendThread;
	bool m_IsSendThreadDye;

	// 전송 주기
	int m_SendInterval;

private:
	// 초기화 함수
	void InitializeAll();		// 전체 초기화

public:
	// 스캔함수
	void Scan(int nicindex);
	// IP 범위만큼 ARP Request
	// 반환값: 보낸 패킷수
	//int SendARP(u_long beginip, u_long end_ip);

	// 패킷 캡쳐 함수
	// @ lpParam: 스레드 파라미터 전송
	static UINT AFX_CDECL CaptureThreadFunc(LPVOID lpParam);
	// 패킷 캡처 시작(sniffer)
	void StartCapture();	
	// 패킷 캡처 종료
	void EndCapture();		
	// 캡처 결과 분석, icmp, arp만 분석
	// WPcapCaptureSocket.StartCapture의 콜백함수로 들어감
	static void Analyze(const uint8_t *param, const uint8_t *packet, const uint8_t *pkthdr);
	static void IPAnalyze(CIPStatusList *ipstatlist, CWPcapCaptureSocket *capsock, const uint8_t *packet, const uint8_t *pkthdr);		// IP 분석
	static void ICMPAnalyze(CIPStatusList *ipstatlist, CWPcapCaptureSocket *capsock, const uint8_t *packet, const uint8_t *pkthdr);		// IP 분석
	static void ARPAnalyze(CIPStatusList *ipstatlist, CWPcapCaptureSocket *capsock, const uint8_t *packet, const uint8_t *pkthdr);	// ARP 분석

	// 패킷 전송 스레드 함수
	static UINT AFX_CDECL SendThreadFunc(LPVOID lpParam);
	// 패킷 전송 시작
	void StartSend();
	// 패킷 전송 종료
	void EndSend();

	// NIC 정보 리스트 가져오기
	CNICInfoList *GetNicInfoList()
	{
		return m_SendSock.GetNICInfoList();
	}
	
	// IPStatus List 가져오기
	CIPStatusList *GetIpStatusList() { return &m_IPStatInfoList; }
	// IPStatusList 아이템 삽입( 중복 제거 및 순서대로)
	void IPStatusListInsertItem(uint32_t hbeginip, uint32_t hendip);
	void IPStatusListInsertItem(uint32_t);
	void IPStatusListDeleteItem(int index);
	
	int GetSendInterval() { return m_SendInterval; }
	void SetSendInterval(int ms) { m_SendInterval = ms; }
	CWPcapSendSocket *GetSendSocket() { return &m_SendSock; }
	CWPcapCaptureSocket *GetCaptureSocket() { return &m_CaptureSock; }

public:
	CNetworkIPScan();
	~CNetworkIPScan();
};

