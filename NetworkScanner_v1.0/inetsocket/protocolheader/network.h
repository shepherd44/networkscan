// 네트워크 계층(LAYER 3) 프로토콜 타입 정의
// ARP, IP, ICMP

#ifndef _NETWORK_H__
#define _NETWORK_H__

// ARP------------------------------------------------
// ARP 하드웨어 타입
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
	ARPREQUEST		= 1,
	ARPREPLY		= 2,
	RARPREQUEST		= 3,
	RARPREPLY		= 4,
	DRARPREQUEST	= 5,
	DRARPREPLY		= 6,
	INARPREQUEST	= 7,
	INARPREPLY		= 8,
	ARPOPCODEEND
};

// ARP 메시지 포맷
typedef struct ARPPacket
{
	unsigned short	htype;
	unsigned short	ptype;
	unsigned char	hlen;
	unsigned short	plen;
	unsigned short	opcode;
	unsigned short	shaddr[6];
	unsigned short	spaddr[4];
	unsigned short	dhaddr[6];
	unsigned short	dpaddr[4];
} ARPPacket, *PARPPacket;

// IPV4----------------------------------------



// ICMP----------------------------------------

#endif	// _NETWORK_H__ //