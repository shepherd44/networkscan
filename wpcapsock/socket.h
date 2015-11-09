// �������� Ÿ�� ����
// 
#ifndef _SOCKET_H__
#define _SOCKET_H__

#include <WinSock2.h>
#include <IPHlpApi.h>
#include <exception>
#include <IcmpAPI.h>

#define HAVE_REMOTE	1
#include "pcap.h"

#include "inetproto.h"
#include "NICInfoList.h"

//#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "iphlpapi.lib")	// �� ��巹�� ��� ���� ���
#pragma comment(lib, "ws2_32.lib")		// iphlpapi ���

#define PACKET_SNAP_LEN	65536
#define NICNAME_OFFSET		12

class CWPcapSocket
{
#ifdef _DEBUG
public:
#else // _DEBUG
protected:
#endif // _DEBUG
	
	// ��Ʈ��ũ ����̽� ����Ʈ
	pcap_if_t *m_pAllNIC;
	// winpcap ����̽� ���� ����
	pcap_t *m_pCapHandler;	
	int m_CurSel;
	// NIC ���� ����Ʈ ���
	CNICInfoList m_NICInfoList;
	// winpcap ���� ����
	char m_ErrBuffer[PCAP_ERRBUF_SIZE];

#ifdef _DEBUG
public:
#else
protected:
#endif
	void SockInit(); // �ʱ�ȭ �Լ�
	void FindNetDevice(); // �۵����� ��Ʈ��ũ ����̽� ã��

public:
	// pcap_t ��Ʈ��ũ �������̽� ����
	void OpenNetDevice(int index = 0);
	// ����̽� �̸����� ����
	void OpenNetDevice(const char *nicname);
	// ���� ����
	void CloseNetDevice();

	// NIC ���� ��ȯ
	int GetNicNumber();
	// ���� ���õ� NIC ��ȣ ��������
	int GetCurrentSelectNICNum();
	// ���� ���õ� NIC ���� ����ü ��������
	const NICInfo *GetCurrentSelectNICInfo();
	// ���� ���õ� NIC �̸� ��������
	char *GetCurrentSelectNICName();
	// ���� ���� ��������
	const char* GetErrorBuffer();
	// NIC���� ����Ʈ ��ȯ
	CNICInfoList *GetNICInfoList();
public:
	CWPcapSocket();
	virtual ~CWPcapSocket();
};

// Exception
class WPcapSocketException : public std::exception
{
public:
	WPcapSocketException(const char *message) : exception(message) { }
};

#endif	// _SOCKET_H__ //