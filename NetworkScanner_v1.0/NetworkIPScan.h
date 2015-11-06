#pragma once

#include "capturesocket.h"
#include "sendsocket.h"
#include "IPStatusList.h"


#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
	#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

// ĸó ������ �Ķ����

// �Ķ���� 3�� ����ü
struct ThreadParams
{
	void *socket;
	void *list;
	void *isend;
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

	// ���� �ֱ�
	int m_SendInterval;

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
	// @ lpParam: ������ �Ķ���� ����
	static UINT AFX_CDECL CaptureThreadFunc(LPVOID lpParam);
	// ��Ŷ ĸó ����
	void StartCapture();	
	// ��Ŷ ĸó ����
	void EndCapture();		
	// ĸó ��� �м�, icmp, arp�� �м�
	// WPcapCaptureSocket.StartCapture�� �ݹ��Լ��� ��
	static void Analyze(const uint8_t *param, const uint8_t *packet);
	static void IPAnalyze(const uint8_t *param, const uint8_t *packet);		// IP �м�
	static void ARPAnalyze(const uint8_t *param, const uint8_t *packet);	// ARP �м�

	// ��Ŷ ���� ������ �Լ�
	static UINT AFX_CDECL SendThreadFunc(LPVOID lpParam);
	// ��Ŷ ���� ����
	void StartSend();
	// ��Ŷ ���� ����
	void EndSend();

	// NIC ���� ����Ʈ ��������
	CNICInfoList *GetNicInfoList()
	{
		return &(m_SendSock.m_NICInfoList);
	}
	
	// IPStatus List ��������
	CIPStatusList *GetIpStatusList() { return &m_IPStatInfoList; }
	// IPStatusList ������ ����( �ߺ� ���� �� �������)
	void IPStatusListInsertItem(uint32_t hbeginip, uint32_t hendip);
	void IPStatusListDeleteItem(int index);
	
	int GetSendInterval() { return m_SendInterval; }
	void SetSendInterval(int ms) { m_SendInterval = ms; }
	CWPcapSendSocket *GetSendSocket() { return &m_SendSock; }
	CWPcapCaptureSocket *GetCaptureSocket() { return &m_CaptureSock; }

public:
	CNetworkIPScan();
	~CNetworkIPScan();
};

