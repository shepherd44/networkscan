//****************************************************************
// Winpcap 이용한 Packet Send Socket
// 현재 가능한 Protocol: ARP, ICMP(불완전)
//****************************************************************
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
	// Winpcap 패킷 전송 함수
	// @ packet: 전송할 메시지
	// @ len: 패킷 길이
	// @ return: 성공 시 0, 실패 시 -1
	int SendPacket(uint8_t *packet, int len);

	// ARP 요청 메시지 전송
	int SendARPRequest(uint32_t dstip);
	// 목적지 MAC 주소 얻기
	// @ dstmac: 목적지 MAC 주소를 반환 받을 버퍼
	// @ dstip: MAC 주소를 얻을 목적지 주소
	// @ return: 성공 시 0, 실패 시 -1 반환
	int GetDstMAC(uint8_t *dstmac, uint32_t dstip, uint32_t timeout);

	// ARP 요청 메시지 작성
	// @ out: 패킷 작성할 위치
	// @ srcmac: 전송자 MAC 주소
	// @ srcip: 전송자 IP 주소
	// @ dstmac: 도착지 MAC 주소
	// @ dstip: 도착지 IP주소
	// @ op: ARP OP Code
	void SetARPRequest(uint8_t *out, uint8_t *srcmac, uint8_t *srcip, uint8_t *dstmac, uint8_t *dstip, uint16_t op);
	
	// ICMP Send
	int SendICMPV4ECHORequest(uint32_t dstip);

	// UDP 전송
	int SendUDP();
	// UDP 헤더 셋팅
	void SetUDP(uint8_t* packet, uint32_t srcip, uint32_t dstip, uint16_t srcport, uint16_t dstport, uint8_t *data, uint16_t datalen);
	uint16_t BytesTo16(unsigned char X, unsigned char Y);
	// UDP 헤더 체크섬 계산
	uint16_t CalculateUDPChecksum(uint8_t *packet, unsigned char* UserData, int UserDataLen, UINT SourceIP, UINT DestIP, USHORT SourcePort, USHORT DestinationPort, UCHAR Protocol);
	
	// ICMP 메시지 작성(체크섬 자동)
	void SetICMPV4Packet(
		uint8_t *out,
		uint8_t type, 
		uint8_t code, 
		uint16_t iden, 
		uint16_t seq, 
		uint8_t *data,
		uint16_t datalen);
	
	// 플래그 옵션 주는 버전 필요
	// ip 옵션 주는 버전 필요

	// IP 패킷 작성
	// @ packet: 패킷 작성할 버퍼 위치
	// @ headerlen: ipv4 header length
	// @ identification:
	// @ flags: 단편화 플래그
	// @ ttl: Time Ti Live
	// @ prototype: 프로토콜 종류
	// @ ischeck: 체크섬 여부, false일 경우 0으로 셋팅
	// @ *ip: ip
	// @ data: ip data 버퍼 위치
	// @ datalen: data 크기
	// @ option: 옵션 버퍼 위치(기본 NULL)
	// @ optionlen: 옵션 길이(기본 0)
	void SetIPPacket(uint8_t *packet, uint16_t headerlen, uint16_t identification, uint16_t flags, uint8_t ttl, uint8_t prototype,
		bool ischeck, uint8_t *srcip, uint8_t *dstip, uint8_t *data, uint16_t datalen,uint8_t *option = NULL, uint16_t optionlen = 0);

	// 이더넷 헤더 셋팅
	// ARP Table과 ARP를 사용하여 상대 맥주소 설정
	// @ packet: 셋팅할 버퍼 위치
	// @ src: 메시지 송신자 맥 주소
	// @ prototype: 프로토콜 타입
	// @ dstip: 목적지 ip 주소
	int SetETHHeaderWithARP(uint8_t *packet, uint8_t *src, uint16_t prototype, uint32_t dstip);
	// 자율 셋팅, 직접 목적지 주소를 셋팅할 때 사용
	void SetETHHeader(uint8_t *packet, uint8_t *dst, uint8_t *src, uint16_t prototype);
	
	// ARP 테이블 가져오기
	// @ pmib: 가져올 위치, 사용 후 free(pmib) 필요
	int GetARPTable(PMIB_IPNETTABLE *pmib);

	// 네트워크 내부의 주소인지 확인
	// @ ip: 확인할 주소
	bool IsInNet(uint32_t ip);

public:
	CWPcapSendSocket();
	virtual ~CWPcapSendSocket();
};

#endif	// _SENDSOCKET_H__ //