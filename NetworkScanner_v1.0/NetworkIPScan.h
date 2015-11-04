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
	// IP ���� ���� ����Ʈ ���
	CIPStatusList m_IPStatInfoList;

	// Socket
	CWPcapSendSocket m_SendSock;		// ������ ���� �� NIC ����
	CWPcapCaptureSocket m_CaptureSock;

	// ������ �ڵ�
	CWinThread *m_hCaptureThread;
	CWinThread *m_hSendThread;
	bool m_IsSendThreadDye;

private:
	// �ʱ�ȭ �Լ�
	void InitializeAll();		// ��ü �ʱ�ȭ

public:
	// ��ĵ�Լ�
	void Scan(int nicindex);
	// IP ������ŭ ARP Request
	// ��ȯ��: ���� ��Ŷ��
	int SendARP(u_long beginip, u_long end_ip);

	// ��Ŷ ĸ�� �Լ�
	static UINT AFX_CDECL CaptureThreadFunc(LPVOID lpParam);	// ��Ŷ ĸó ������ �Լ�
	void StartCapture();	// ĸó ����
	void EndCapture();		// ĸó ����
	// ĸó ��� �м�, icmp, arp�� �м�
	// WPcapCaptureSocket.StartCapture�� �ݹ��Լ��� ��
	static void Analyze(const uint8_t *param, const uint8_t *packet);
	static void IPAnalyze(const uint8_t *param, const uint8_t *packet);		// IP �м�
	static void ARPAnalyze(const uint8_t *param, const uint8_t *packet);	// ARP �м�

	static UINT AFX_CDECL SendThreadFunc(LPVOID lpParam);		// ��Ŷ ���� ������ �Լ�
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

