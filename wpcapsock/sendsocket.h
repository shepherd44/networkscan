// 프로토콜 타입 정의
// 
#ifndef _SENDSOCKET_H__
#define _SENDSOCKET_H__

#include "inetproto.h"
#include "socket.h"

class CWPcapSendSocket : public CWPcapSocket
{
#ifdef _DEBUG
public:
#else // _DEBUG
protected:
#endif // _DEBUG
	uint8_t *m_Packet;
	int m_PacketLen;
	uint8_t m_GatewayMAC[MACADDRESS_LENGTH];
	uint8_t m_GatewayIP[IPV4ADDRESS_LENGTH];

public:
	// 패킷 전송
	int SendPacket(uint8_t *packet, int len);
	// ARP 요청 메시지 전송
	int SendARPRequest(uint32_t dstip);
	// 목적지 MAC 주소 얻기
	// 성공 시 0, 실패 시 -1 반환
	int GetDstMAC(uint8_t *dstmac, uint32_t dstip);

	
	// ARP 요청 메시지 작성
	void SetARPRequest(uint8_t *out,
		uint8_t *srcmac,
		uint8_t *srcip,
		uint8_t *dstmac,
		uint8_t *dstip,
		uint16_t op);	
	
	// ICMP Send
	void SendPingInWin(uint32_t dstip);			// 가짜, 윈도우 함수 사용 버전
	void SendICMPV4ECHORequest(uint32_t dstip);	// 현재 에러, 응답이 없음

	// ICMP 메시지 작성
	void SetICMPV4Packet(
		uint8_t *out,
		uint8_t type, 
		uint8_t code, 
		uint16_t iden, 
		uint16_t seq, 
		uint8_t *data,
		uint16_t datalen);
	
	// IP 패킷 작성
	// 플래그 옵션 주는 버전 필요
	// ip 옵션 주는 버전 필요
	void SetIPPacket(
		uint8_t *packet,
		uint16_t headerlen,
		uint16_t identification,
		uint16_t flags,
		uint8_t prototype,
		uint8_t *srcip,
		uint8_t *dstip,
		uint8_t *data,
		uint16_t datalen);

	// 이더넷 헤더 셋팅
	// ARP Table과 ARP를 사용하여 상대 맥주소 설정
	// 작성중
	int SetETHHeaderWithARP(
		uint8_t *packet,		// (out)패킷 시작 주소
		uint8_t *src,			// 메세지 송신자 맥 주소
		uint16_t prototype,		// 프로토콜 타입
		uint32_t dstip);		// 목적지 ip 주소
	void SetETHHeader(uint8_t *packet, uint8_t *dst, uint8_t *src, uint16_t prototype);			// 자율 셋팅, 직접 이더넷을 셋팅할 때 사용
	int GetARPTable(PMIB_IPNETTABLE *pmib);

	// 네트워크 내부의 주소인지 확인
	// 테스트 필요
	bool IsInNet(uint32_t ip);

public:
	CWPcapSendSocket();
	virtual ~CWPcapSendSocket();
};

#endif	// _SENDSOCKET_H__ //