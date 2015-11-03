#pragma once

#include "ARPSocket.h"
#include "IPStatusInfoVector.h"

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
	#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

class CNetworkIPScan
{
private:
	//IP Address
	u_long m_BeginIP;
	u_long m_EndIP;

	// IP 상태 저장 리스트 헤더
	CIPStatusInfoVector m_vhIPStatusInfo;

	// ARP Socket
	CARPSocket m_ARPRequestSock;	// SendSocket
	CARPSocket m_ARPCaptureSock;	// CaptureSocket

	// NIC 정보
	u_char m_NICMACAddress[6];
	u_char m_NICIPAddress[4];
	u_char m_NICNetmask[4];
	u_char m_GatewayIPAddress[4];

	// 쓰레드 핸들
	HANDLE m_hCaptureThread;

private:
	// 초기화 함수
	void InitializeAll();		// 전체 초기화
	void AdapterInfoInit();		// 아답터 정보 초기화

public:
	// 스캔함수
	void Scan(u_long begin, u_long end);
	// IP 범위만큼 ARP Request
	// 반환값: 보낸 패킷수
	int SendARP(u_long beginip, u_long end_ip);

	// 패킷 캡쳐 함수
	void StartCapture();	// 캡처 시작
	void EndCapture();		// 캡처 종료
	static DWORD WINAPI ARPCaptueThreadFunc(LPVOID lpParam);	// 패킷 캡처 스레드 함수
	void Analyze();			// 캡쳐 데이터 분석
	
	// NIC 정보 Get
	u_char* GetNICMACAddress() { return m_NICMACAddress; }
	u_char* GetNICIPAddress() { return m_NICIPAddress; }
	u_char* GetNICNetmask() { return m_NICNetmask; }
	u_char* GetGatewayIPAddress() { return m_GatewayIPAddress; }
	CIPStatusInfoVector& GetIPStatusVector() { return m_vhIPStatusInfo; }

	// 오퍼레이터[]
	IPStatusInfo& operator[] (int index) { return m_vhIPStatusInfo[index]; }

public:
	CNetworkIPScan();
	~CNetworkIPScan();
};

