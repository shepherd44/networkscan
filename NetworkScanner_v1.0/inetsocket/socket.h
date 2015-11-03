// 프로토콜 타입 정의
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
	// 네트워크 디바이스 리스트
	pcap_if_t *m_pNetDevice;
	// winpcap 디바이스 연결 소켓
	pcap_t *m_pCapHandler;
	
	// netmask, macaddress, ip
	u_int m_Netmask;
	u_char m_MyMACAddress[6];
	u_char m_MyIPAddress[4];

	// winpcap 에러 버퍼
	char m_ErrBuffer[PCAP_ERRBUF_SIZE];

protected:
	// 초기화 함수
	void SockInit();
	
	// 작동중인 네트워크 디바이스 찾기
	void FindNetDevice();
	// 네트워크 인터페이스 연결
	void OpenNetDevice();
	// 네트워크 인터페이스 정보 얻기
	// MAC, IP, NETMASK
	void GetNICInfo();

public:
	CPcapSocket();
	~CPcapSocket();
};

#endif	// _SOCKET_H__ //