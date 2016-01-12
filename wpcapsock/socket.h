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

#pragma comment(lib, "iphlpapi.lib")	// �� ��巹�� ��� ���� ���
#pragma comment(lib, "ws2_32.lib")		// iphlpapi ���

#define PACKET_SNAP_LEN		65536
#define NICNAME_OFFSET		12

class CWPcapSocket
{	
protected:
	// ��Ʈ��ũ ����̽� ����Ʈ
	pcap_if_t *m_pAllNIC;
	// winpcap ����̽� ���� ����
	pcap_t *m_pCapHandler;
	int m_CurSel;
	// NIC ���� ����Ʈ ���
	CNICInfoList m_NICInfoList;
	// winpcap ���� ����
	char m_ErrBuffer[PCAP_ERRBUF_SIZE];

	void SockInit(); // �ʱ�ȭ �Լ�
public:
	// �۵����� ��Ʈ��ũ ����̽� ã��
	void FindNetDevice();
	// pcap_t ��Ʈ��ũ �������̽� ����
	void OpenNetDevice(int index = 0);
	// ����̽� �̸����� ����
	void OpenNetDevice(const char *nicname);
	// ���� ����
	void CloseNetDevice();

	// ���� ����� NIC ���� ��ȯ
	int GetNICCount();
	// ���� ���õ� NIC ��ȣ ��������
	// ������ -1 ��ȯ
	int GetCurrentSelectNICNum();
	// ���� ���õ� NIC ���� ����ü ��������
	// ���õ� NIC�� ������ NULL ��ȯ
	const NICInfo *GetCurrentSelectNICInfo();
	// ���� ���õ� NIC �̸� ��������
	// ���õ� NIC�� ������ NULL ��ȯ
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