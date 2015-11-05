// 데이터링크 계층(레이어 2) 프로토콜 타입 정의
// 이더넷

#ifndef _INETPROTO_H__
#define _INETPROTO_H__

#include <stdint.h>
#include <iostream>
// ethernet------------------------------------

#define ETHERNETHEADER_LENGTH	14
#define MACADDRESS_LENGTH		6
#define IPV4ADDRESS_LENGTH		4

enum ETHTYPE
{
	NOTING	= 0x0,
	IPV4	= 0x0800,
	ARP		= 0x0806,
	RARP	= 0x8035,
	WAKEONLAN = 0x0842,
	IPV6	= 0x86DD,

	MACSECURITY = 0x88E5,
	PROTOCOLTYPEEND = 0x10000
};

struct ETHHeader
{
	uint8_t srcmac[6];
	uint8_t dstmac[6];
	uint16_t prototype;
};

// ARP-------------------------------------------
// ARP 하드웨어 타입
#define ARPMESSAGE_LENGTH	60
#define ARPHEADER_LENGTH	28

enum ARPHRD
{
	ETHERNET	= 1,
	IEEE802		= 6,
	ARCNET		= 7,
	HYPERCHNNEL = 8,
	LANSTAR		= 9,
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
	uint16_t	htype;
	uint16_t	ptype;
	uint8_t		hlen;
	uint8_t		plen;
	uint16_t	opcode;
	uint8_t		shaddr[6];
	uint8_t		spaddr[4];
	uint8_t		dhaddr[6];
	uint8_t		dpaddr[4];
} ARPPacket, *PARPPacket;


void SetARPPacket(uint8_t *out,
				  uint8_t htype,
				  uint8_t ptype,
				  uint8_t hlen,
				  uint8_t plen,
				  uint16_t opcode,
				  uint8_t *srcmac,
				  uint8_t *srcip,
				  uint8_t *dstmac,
				  uint8_t *dstip
				  );

void SetARPRequest(uint8_t* out,
				   uint8_t *srcmac,
				   uint8_t *srcip,
				   uint8_t *dstmac,
				   uint8_t *dstip);

// IPV4----------------------------------------

enum IPV4TYPE
{
	HOTOPT = 0,
	ICMP = 1,
	IGMP = 2,
	GGP = 3,
	IPV4_IPV4 = 4,
	ST = 5,
	TCP = 6,
	CBT = 7,
	EGP = 8,
	IGP = 9,
	BBN_RCC_MON = 10,
	NVP_2 = 11,
	PUP = 12,
	ARGUS = 13,
	EMCON = 14,
	CHAOS = 16,
	UDP = 17,
	
	IPV6_IPV4 = 41,

	RESERVED = 255,

	END
};

#define IPV4HEADER_BASICLENGTH	20	// bytes
#define IPV4HEADER_MAX_LENGTH	60	// bytes

#define SETRESERVED(bit)
#define SETDF(bit)
#define SETMF(bit)
#define SETFLAGSOFF()
typedef struct IPV4Header
{
	uint8_t		headerlen : 4;	// IP 버전
	uint8_t		version : 4;		// IP 헤더 길이(옵션 포함길이)
	uint8_t		tos;			// type of service
	uint16_t	totallen;		// IP전체 길이
	uint16_t	identification;	//6b
	
	uint16_t	flags;
	
	uint8_t		ttl;
	uint8_t		protoid;
	uint16_t	checksum;
	uint8_t		srcaddr[4];
	uint8_t		dstaddr[4];
	//uint32_t	option;		//옵션이 가변 길이 ihl로 확인
}IPV4Header, *PIPV4Header;

// IP Header Checksum 계산
// @ iph_len: byte단위 헤더 길이
// @ piph: 헤더 시작 위치
uint16_t IPHeaderChecksum(uint16_t iph_len, uint8_t *piph);


// ICMP----------------------------------------
enum ICMPV4TYPE
{
	ICMPV4_ECHO_REPLY		= 0,
	ICMPV4_DST_UNREACH		= 3,		// Destination Unrechable
	ICMPV4_REDIRECT			= 5,
	ICMPV4_ECHO_REQUEST		= 8,
	ICMPV4_ROUTER_AD		= 9,
	ICMPV4_ROUTER_SOLICIT	= 10,
	ICMPV4_TIMESTAMP_REQUEST	= 13,
	ICMPV4_TIMESTAMP_REPLY = 14,
	ICMPV4_INFO_REQUEST		= 15,
	ICMPV4_INFO_REPLY		= 16,
	ICMPV4_MASK_REQUEST		= 17, // Address Mask Request.
	ICMPV4_MASK_REPLY		= 18, // Address Mask Reply.
	ICMPV4_MOBILE_REG_REQUEST	= 35,	// Mobile Registration request
	ICMPV4_MOBILE_REG_REPLY	= 36	// Mobile Registration reply
};

#define ICMPV4HEADER_LENGTH		8	// bytes
#define ICMPV4ECHO_LENGTH		40
// ICMPV4 헤더 체크섬 계산
// @ len: 헤더의 길이(ip 전체길이 - ip헤더 길이)
// @ picmph: 헤더의 위치
#define ICMPV4HeaderChecksum(len, picmph)		IPHeaderChecksum(len, picmph)

typedef struct ICMPV4Header
{
	uint8_t		type;
	uint8_t		code;
	uint16_t	checksum;
	uint16_t	identifier;
	uint16_t	seqnum;
	// + 데이터
}ICMPV4Header, *PICMPV4Header;

// TCP------------------------

typedef struct PseudoHeader
{
	uint32_t  src_addr;	//IP의 source address
	uint32_t  dst_addr;	//IP의 dest address
	uint8_t  useless;	//예약된 필드(0x00)
	uint8_t  protocol;	//IP의 Protocol
	uint16_t length;		// tcp : (ip total lenth)-(ip header length)   udp : udp_header len;
}PseudoHeader;

typedef struct TCPHeader
{
	uint16_t	srcport;
	uint16_t	dstport;
	uint32_t	seqnum;
	uint32_t	acknum;
	uint16_t	dataoff : 4;
	uint16_t	reserved : 3;
	uint16_t	flags : 9;
	uint16_t	window;
	uint16_t	checksum;
	uint16_t	urgpointer;
	
} TCPHeader, *PTCPHeader;


// UDP------------------------

#define UDPHEADER_LENGTH	8

typedef struct UDPHeader
{
	uint16_t	srcport;
	uint16_t	dstport;
	uint16_t	udplen;
	uint16_t	checksum;
} UDPHeader, *PUDPHeader;

#endif	// _INETPROTO_H__ //