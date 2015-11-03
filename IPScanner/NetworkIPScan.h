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

	// IP ���� ���� ����Ʈ ���
	CIPStatusInfoVector m_vhIPStatusInfo;

	// ARP Socket
	CARPSocket m_ARPRequestSock;	// SendSocket
	CARPSocket m_ARPCaptureSock;	// CaptureSocket

	// NIC ����
	u_char m_NICMACAddress[6];
	u_char m_NICIPAddress[4];
	u_char m_NICNetmask[4];
	u_char m_GatewayIPAddress[4];

	// ������ �ڵ�
	HANDLE m_hCaptureThread;

private:
	// �ʱ�ȭ �Լ�
	void InitializeAll();		// ��ü �ʱ�ȭ
	void AdapterInfoInit();		// �ƴ��� ���� �ʱ�ȭ

public:
	// ��ĵ�Լ�
	void Scan(u_long begin, u_long end);
	// IP ������ŭ ARP Request
	// ��ȯ��: ���� ��Ŷ��
	int SendARP(u_long beginip, u_long end_ip);

	// ��Ŷ ĸ�� �Լ�
	void StartCapture();	// ĸó ����
	void EndCapture();		// ĸó ����
	static DWORD WINAPI ARPCaptueThreadFunc(LPVOID lpParam);	// ��Ŷ ĸó ������ �Լ�
	void Analyze();			// ĸ�� ������ �м�
	
	// NIC ���� Get
	u_char* GetNICMACAddress() { return m_NICMACAddress; }
	u_char* GetNICIPAddress() { return m_NICIPAddress; }
	u_char* GetNICNetmask() { return m_NICNetmask; }
	u_char* GetGatewayIPAddress() { return m_GatewayIPAddress; }
	CIPStatusInfoVector& GetIPStatusVector() { return m_vhIPStatusInfo; }

	// ���۷�����[]
	IPStatusInfo& operator[] (int index) { return m_vhIPStatusInfo[index]; }

public:
	CNetworkIPScan();
	~CNetworkIPScan();
};

