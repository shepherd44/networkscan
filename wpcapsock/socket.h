// 프로토콜 타입 정의
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
#pragma comment(lib, "iphlpapi.lib")	// 맥 어드레스 얻기 위해 사용
#pragma comment(lib, "ws2_32.lib")		// iphlpapi 사용

#define PACKET_SNAP_LEN	65536
#define NICNAME_OFFSET		12

class CWPcapSocket
{
#ifdef _DEBUG
public:
#else // _DEBUG
protected:
#endif // _DEBUG
	
	pcap_if_t *m_pAllNIC;	// 네트워크 디바이스 리스트
	pcap_t *m_pCapHandler;	// winpcap 디바이스 연결 소켓
	int m_CurSel;
	// netmask, macaddress, ip
	CNICInfoList m_NICInfoList;

	// winpcap 에러 버퍼
	char m_ErrBuffer[PCAP_ERRBUF_SIZE];

#ifdef _DEBUG
public:
#else
protected:
#endif
	void SockInit(); // 초기화 함수
	void FindNetDevice(); // 작동중인 네트워크 디바이스 찾기

public:
	// pcap_t 네트워크 인터페이스 연결
	void OpenNetDevice(int index = 0);
	void OpenNetDevice(const char *nicname);
	void CloseNetDevice();

	// NIC 갯수 반환
	int GetNicNumber();
	int GetCurrentSelectNICNum();
	const NICInfo *GetCurrentSelectNICInfo();
	char *GetCurrentSelectNICName();
	const char* GetErrorBuffer();
	void GetNICInfo();

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