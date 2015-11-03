// ��Ʈ��ũ ����(LAYER 3) �������� Ÿ�� ����
// ARP, IP, ICMP

#ifndef _NETWORK_H__
#define _NETWORK_H__

// ARP------------------------------------------------
// ARP �ϵ���� Ÿ��
enum ARPHRD
{
	ETHERNET	= 1,
	IEEE802		= 6,
	ARCNET		= 7,
	HYPERCHNNEL = 8,
	LANSTAR		= 9,
	ARPHRDEND
};

// ARP OPCODE ����
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

// ARP �޽��� ����
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