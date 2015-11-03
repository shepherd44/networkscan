// �������� Ÿ�� ����
// 
#ifndef _SOCKET_H__
#define _SOCKET_H__

#include <IPHlpApi.h>
#include <netioapi.h>
#include <WinSock2.h>

#include "WpdPack\Include\pcap.h"
#include "protocolheader.h"

class CPcapSocket
{
	// ��Ʈ��ũ ����̽� ����Ʈ
	pcap_if_t *m_pNetDevice;
	// winpcap ����̽� ���� ����
	pcap_t *m_pCapHandler;
	
	// netmask, macaddress, ip
	u_int m_Netmask;
	u_char m_MyMACAddress[6];
	u_char m_MyIPAddress[4];

	// winpcap ���� ����
	char m_ErrBuffer[PCAP_ERRBUF_SIZE];

protected:
	// �ʱ�ȭ �Լ�
	void SockInit();
	
	// �۵����� ��Ʈ��ũ ����̽� ã��
	void FindNetDevice();
	// ��Ʈ��ũ �������̽� ����
	void OpenNetDevice();
	// ��Ʈ��ũ �������̽� ���� ���
	// MAC, IP, NETMASK
	void GetNICInfo();

public:
	CPcapSocket();
	~CPcapSocket();
};

#endif	// _SOCKET_H__ //