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


// 프로토콜 타입
enum PROTOCOLTYPE
{
	IPV4 = 0x0800,
	ARP = 0x0806,
	PROTOCOLTYPEEND
};

// ARP 하드웨어 타입
enum ARPHRD
{
	ETHERNET = 1,
	IEEE802 = 6,
	ARCNET = 7,
	HYPERCHNNEL = 8,
	LANSTAR = 9,
	ARPHRDEND
};

// ARP OPCODE 종류
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

// ARP 메시지 포맷
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
	// 네트워크 디바이스 
	pcap_if_t *m_pNetDevice;
	// winpcap 디바이스 연결 소켓
	pcap_t *m_pCapHandler;
	// winpcap 패킷 캡쳐 필터
	char *m_pPacketFilter;
	// winpcap 프로그램된 필터
	struct bpf_program m_FilterCode;
	// 캡쳐하는 시간
	int m_CatureTime;

	// netmask, macaddress, ip
	u_int m_Netmask;
	u_char m_MyMACAddress[6];
	u_char m_MyIPAddress[4];

	// winpcap 에러 버퍼
	char m_ErrBuffer[PCAP_ERRBUF_SIZE];

	// 패킷 캡쳐를 할 경우 사용하는 출력 리스트
	// 다시 캡쳐할 경우 이전 데이터 지워짐
	std::list<ARPPacket> m_LHCapturedPacket;

protected:
	// 초기화 함수
	void SockInit();

	// winpcap 패킷 캡쳐 콜백 함수
	static void ARPCaptureCallBack(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
	// 작동중인 네트워크 디바이스 찾기
	void FindNetDevice();
	// 네트워크 인터페이스 연결
	void OpenNetDevice();
	// 네트워크 인터페이스 정보 얻기
	// MAC, IP, NETMASK
	void GetNICInfo();

	// 패킷 만들기
	void SetEthHeader(u_char *out, u_char *srcmac, u_char *dstmac);	// ethernet packet
	void SetARPPacket(u_char *out, u_char *srcmac, u_char *srcip, u_char *dstmac, u_char *dstip);	// arp packet
	
public:
	CARPSocket();
	~CARPSocket();

public:
	// 패킷 보내기
	int SendPacket(u_long dstip);
	int SendPacket(u_long srcip, u_long dstip);
	// 패킷 캡쳐
	// @pckcnt = 캡쳐할 패킷 개수(Default = 0, 무제한)
	void StartCapture(int pckcnt = 0);
	// 캡쳐 끝내기
	void EndCapture();
	// 캡쳐 결과 리스트 관련 함수
	void CaptureListClear() { return m_LHCapturedPacket.clear(); }
	int GetCaptureListLength() { return m_LHCapturedPacket.size(); }
	std::list<ARPPacket>::iterator GetCaptureListBegin() { return m_LHCapturedPacket.begin(); }
	std::list<ARPPacket>::iterator GetCaptureListEnd() { return m_LHCapturedPacket.end(); }
	ARPPacket GetARPPacket(int index);
};

