#pragma once

#include "capturesocket.h"
#include "sendsocket.h"
#include "IPStatusList.h"


#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
	#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

struct CaptureParam
{
	CWPcapCaptureSocket *param_capsock;
	CIPStatusList *param_ipstatlist;
};

struct Params
{
	void *param1;
	void *param2;
	void *param3;
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

private:
	// 초기화 함수
	void InitializeAll();		// 전체 초기화

public:
	// 스캔함수
	void Scan(int nicindex);
	// IP 범위만큼 ARP Request
	// 반환값: 보낸 패킷수
	int SendARP(u_long beginip, u_long end_ip);

	// 패킷 캡쳐 함수
	static UINT AFX_CDECL CaptureThreadFunc(LPVOID lpParam);	// 패킷 캡처 스레드 함수
	void StartCapture();	// 캡처 시작
	void EndCapture();		// 캡처 종료
	// 캡처 결과 분석, icmp, arp만 분석
	// WPcapCaptureSocket.StartCapture의 콜백함수로 들어감
	static void Analyze(const uint8_t *param, const uint8_t *packet);
	static void IPAnalyze(const uint8_t *param, const uint8_t *packet);		// IP 분석
	static void ARPAnalyze(const uint8_t *param, const uint8_t *packet);	// ARP 분석

	static UINT AFX_CDECL SendThreadFunc(LPVOID lpParam);		// 패킷 센드 스레드 함수
	void StartSend();
	void EndSend();

	CNICInfoList *GetNicInfoList()
	{
		return &(m_SendSock.m_NICInfoList);
	}
	
	CIPStatusList *GetIpStatusList() { return &m_IPStatInfoList; }
public:
	CNetworkIPScan();
	~CNetworkIPScan();
};

