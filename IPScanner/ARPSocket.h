#pragma once
#include <list>
#include <iostream>

#include <WinSock2.h>
#include <IPHlpApi.h>
#include <netioapi.h>

#include "pcap.h"

#define ARPPACKETSIZE			60
#define MACADDRESSLENGTH		6
#define IPV4ADDRESSLENGTH		4
#define ETHERNETHEADERLENGTH	14


// �������� Ÿ��
enum PROTOCOLTYPE
{
	IPV4 = 0x0800,
	ARP = 0x0806,
	PROTOCOLTYPEEND
};

// ARP �ϵ���� Ÿ��
enum ARPHRD
{
	ETHERNET = 1,
	IEEE802 = 6,
	ARCNET = 7,
	HYPERCHNNEL = 8,
	LANSTAR = 9,
	ARPHRDEND
};

// ARP OPCODE ����
enum ARPOPCODE
{
	ARPREQUEST = 1,
	ARPREPLY = 2,
	RARPREQUEST = 3,
	RARPREPLY = 4,
	DRARPREQUEST = 5,
	DRARPREPLY = 6,
	INARPREQUEST = 7,
	INARPREPLY = 8,
	ARPOPCODEEND
};

// ARP �޽��� ����
typedef struct ARPPacket
{
	u_int16_t	htype;
	u_int16_t	ptype;
	u_char		hlen;
	u_char		plen;
	u_int16_t	opcode;
	u_char		shaddr[6];
	u_char		spaddr[4];
	u_char		dhaddr[6];
	u_char		dpaddr[4];
} ARPPacket;

class CARPSocket
{
protected:
	// ��Ʈ��ũ ����̽� 
	pcap_if_t *m_pNetDevice;
	// winpcap ����̽� ���� ����
	pcap_t *m_pCapHandler;
	// winpcap ��Ŷ ĸ�� ����
	char *m_pPacketFilter;
	// winpcap ���α׷��� ����
	struct bpf_program m_FilterCode;
	// ĸ���ϴ� �ð�
	int m_CatureTime;

	// netmask, macaddress, ip
	u_int m_Netmask;
	u_char m_MyMACAddress[6];
	u_char m_MyIPAddress[4];

	// winpcap ���� ����
	char m_ErrBuffer[PCAP_ERRBUF_SIZE];

	// ��Ŷ ĸ�ĸ� �� ��� ����ϴ� ��� ����Ʈ
	// �ٽ� ĸ���� ��� ���� ������ ������
	std::list<ARPPacket> m_LHCapturedPacket;

protected:
	// �ʱ�ȭ �Լ�
	void SockInit();

	// winpcap ��Ŷ ĸ�� �ݹ� �Լ�
	static void ARPCaptureCallBack(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
	// �۵����� ��Ʈ��ũ ����̽� ã��
	void FindNetDevice();
	// ��Ʈ��ũ �������̽� ����
	void OpenNetDevice();
	// ��Ʈ��ũ �������̽� ���� ���
	// MAC, IP, NETMASK
	void GetNICInfo();

	// ��Ŷ �����
	void SetEthHeader(u_char *out, u_char *srcmac, u_char *dstmac);	// ethernet packet
	void SetARPPacket(u_char *out, u_char *srcmac, u_char *srcip, u_char *dstmac, u_char *dstip);	// arp packet
	
public:
	CARPSocket();
	~CARPSocket();

public:
	// ��Ŷ ������
	int SendPacket(u_long dstip);
	int SendPacket(u_long srcip, u_long dstip);
	// ��Ŷ ĸ��
	// @pckcnt = ĸ���� ��Ŷ ����(Default = 0, ������)
	void StartCapture(int pckcnt = 0);
	// ĸ�� ������
	void EndCapture();
	// ĸ�� ��� ����Ʈ ���� �Լ�
	void CaptureListClear() { return m_LHCapturedPacket.clear(); }
	int GetCaptureListLength() { return m_LHCapturedPacket.size(); }
	std::list<ARPPacket>::iterator GetCaptureListBegin() { return m_LHCapturedPacket.begin(); }
	std::list<ARPPacket>::iterator GetCaptureListEnd() { return m_LHCapturedPacket.end(); }
	ARPPacket GetARPPacket(int index);
};

