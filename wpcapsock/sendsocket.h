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
	// 가짜, 윈도우 함수 사용 버전
	void SendPingInWin(uint32_t dstip);
	// 현재 에러, 응답이 없음
	int SendICMPV4ECHORequest(uint32_t dstip);

	int SendUDP()
	{
		NICInfo *nicinfo = m_NICInfoList.At(m_CurSel);
		uint16_t packetlen = UDPHEADER_LENGTH + IPV4HEADER_BASICLENGTH + ETHERNETHEADER_LENGTH;
		uint16_t udplen = UDPHEADER_LENGTH;
		uint16_t ipheaderlen = IPV4HEADER_BASICLENGTH;
		uint16_t ethlen = ETHERNETHEADER_LENGTH;
		uint8_t *packet = (uint8_t *)malloc(packetlen);
		memset(packet, 0, packetlen);

		uint8_t *pudp = (packet + ipheaderlen + ethlen);
		uint16_t datalen = udplen - ICMPV4HEADER_LENGTH;
		uint8_t *data = (uint8_t *)malloc(datalen);
		uint16_t i = 0;

		// UDP 데이터 셋팅
		memset(data, 0, datalen);
		for (int i = 0; i < datalen; i++)
			data[i] = i + 0x44;
		
		uint32_t dstip = inet_addr("172.16.5.201");
		SetUDP(packet, nicinfo->NICIPAddress, dstip, 1300, 1300, data,  datalen);
		free(data);

		// IP 헤더 셋팅(-단편화 고려 x-)
		uint8_t *pip = packet + ethlen;
		datalen += ICMPV4HEADER_LENGTH;
		SetIPPacket(
			pip,
			IPV4HEADER_BASICLENGTH,
			0x3713,
			0x0000,
			128,
			IPV4TYPE::UDP,
			true,
			(uint8_t *)&nicinfo->NICIPAddress,
			(uint8_t *)&dstip,
			(uint8_t *)pudp,
			datalen);

		// 이더넷 헤더 셋팅
		SetETHHeaderWithARP(packet, nicinfo->NICMACAddress, htons(ETHTYPE::IPV4), dstip);
		// 패킷 전송
		int ret = SendPacket(packet, packetlen);
		return ret;
	}
	void SetUDP(uint8_t* packet, uint32_t srcip, uint32_t dstip, uint16_t srcport, uint16_t dstport, uint8_t *data, uint16_t datalen)
	{
		USHORT TotalLen = datalen + 20 + 8;
		//Beginning of UDP Header
		uint16_t TmpType;
		//// Beginning of IP Header
		//memcpy((void*)(packet + 14), (void*)"\x45", 1); //The Version (4) in the first 3 bits  and the header length on the last 5. (Im not sure, if someone could correct me plz do)
		////If you wanna do any IPv6 stuff, you will need to change this. but i still don't know how to do ipv6 myself =s 
		//memcpy((void*)(packet + 15), (void*)"\x00", 1); //Differntiated services field. Usually 0 
		//TmpType = htons(TotalLen);
		//memcpy((void*)(packet + 16), (void*)&TmpType, 2);
		//TmpType = htons(0x1337);
		//memcpy((void*)(packet + 18), (void*)&TmpType, 2);// Identification. Usually not needed to be anything specific, esp in udp. 2 bytes (Here it is 0x1337
		//memcpy((void*)(packet + 20), (void*)"\x00", 1); // Flags. These are not usually used in UDP either, more used in TCP for fragmentation and syn acks i think 
		//memcpy((void*)(packet + 21), (void*)"\x00", 1); // Offset
		//memcpy((void*)(packet + 22), (void*)"\x80", 1); // Time to live. Determines the amount of time the packet can spend trying to get to the other computer. (I see 128 used often for this)
		//memcpy((void*)(packet + 23), (void*)"\x11", 1);// Protocol. UDP is 0x11 (17) TCP is 6 ICMP is 1 etc
		//memcpy((void*)(packet + 24), (void*)"\x00\x00", 2); //checksum 
		//memcpy((void*)(packet + 26), (void*)&srcip, 4); //inet_addr does htonl() for us
		//memcpy((void*)(packet + 30), (void*)&dstip, 4);
		//Beginning of UDP Header
		TmpType = htons(srcport);
		memcpy((void*)(packet + 34), (void*)&TmpType, 2);
		TmpType = htons(dstport);
		memcpy((void*)(packet + 36), (void*)&TmpType, 2);
		USHORT UDPTotalLen = htons(datalen + 8); // UDP Length does not include length of IP header
		memcpy((void*)(packet + 38), (void*)&UDPTotalLen, 2);
		//memcpy((void*)(FinalPacket+40),(void*)&TmpType,2); //checksum
		memcpy((void*)(packet + 42), (void*)data, datalen);

		unsigned short UDPChecksum = CalculateUDPChecksum(packet, data, datalen, srcip, dstip, htons(srcport), htons(dstport), 0x11);
		memcpy((void*)(packet + 40), (void*)&UDPChecksum, 2);
	}
	unsigned short BytesTo16(unsigned char X, unsigned char Y)
	{
		unsigned short Tmp = X;
		Tmp = Tmp << 8;
		Tmp = Tmp | Y;
		return Tmp;
	}
	unsigned short CalculateUDPChecksum(uint8_t *packet, unsigned char* UserData, int UserDataLen, UINT SourceIP, UINT DestIP, USHORT SourcePort, USHORT DestinationPort, UCHAR Protocol)
	{
		unsigned short CheckSum = 0;
		unsigned short PseudoLength = UserDataLen + 8 + 9; //Length of PseudoHeader = Data Length + 8 bytes UDP header (2Bytes Length,2 Bytes Dst Port, 2 Bytes Src Port, 2 Bytes Checksum)
		//+ Two 4 byte IP's + 1 byte protocol
		PseudoLength += PseudoLength % 2; //If bytes are not an even number, add an extra.
		unsigned short Length = UserDataLen + 8; // This is just UDP + Data length. needed for actual data in udp header

		unsigned char* PseudoHeader = new unsigned char[PseudoLength];
		for (int i = 0; i < PseudoLength; i++){ PseudoHeader[i] = 0x00; }

		PseudoHeader[0] = 0x11;

		memcpy((void*)(PseudoHeader + 1), (void*)(packet + 26), 8); // Source and Dest IP

		Length = htons(Length);
		memcpy((void*)(PseudoHeader + 9), (void*)&Length, 2);
		memcpy((void*)(PseudoHeader + 11), (void*)&Length, 2);

		memcpy((void*)(PseudoHeader + 13), (void*)(packet + 34), 2);
		memcpy((void*)(PseudoHeader + 15), (void*)(packet + 36), 2);

		memcpy((void*)(PseudoHeader + 17), (void*)UserData, UserDataLen);


		for (int i = 0; i < PseudoLength; i += 2)
		{
			unsigned short Tmp = BytesTo16(PseudoHeader[i], PseudoHeader[i + 1]);
			unsigned short Difference = 65535 - CheckSum;
			CheckSum += Tmp;
			if (Tmp > Difference){ CheckSum += 1; }
		}
		CheckSum = ~CheckSum; //One's complement
		return CheckSum;
	}
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