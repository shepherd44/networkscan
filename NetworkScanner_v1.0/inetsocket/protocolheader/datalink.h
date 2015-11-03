// 데이터링크 계층(레이어 2) 프로토콜 타입 정의
// 이더넷
#ifndef _DATALINK_H__
#define _DATALINK_H__

// eternet------------------------------------

enum ETH_PROTOCOLTYPE
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
	unsigned char srcmac[6];
	unsigned char dstmac[6];
	unsigned short prototype;
};

#endif	// _DATALINK_H__ //