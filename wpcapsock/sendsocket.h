//****************************************************************
// Winpcap �̿��� Packet Send Socket
// ���� ������ Protocol: ARP, ICMP(�ҿ���)
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
	// Winpcap ��Ŷ ���� �Լ�
	// @ packet: ������ �޽���
	// @ len: ��Ŷ ����
	// @ return: ���� �� 0, ���� �� -1
	int SendPacket(uint8_t *packet, int len);

	// ARP ��û �޽��� ����
	int SendARPRequest(uint32_t dstip);
	// ������ MAC �ּ� ���
	// @ dstmac: ������ MAC �ּҸ� ��ȯ ���� ����
	// @ dstip: MAC �ּҸ� ���� ������ �ּ�
	// @ return: ���� �� 0, ���� �� -1 ��ȯ
	int GetDstMAC(uint8_t *dstmac, uint32_t dstip, uint32_t timeout);

	// ARP ��û �޽��� �ۼ�
	// @ out: ��Ŷ �ۼ��� ��ġ
	// @ srcmac: ������ MAC �ּ�
	// @ srcip: ������ IP �ּ�
	// @ dstmac: ������ MAC �ּ�
	// @ dstip: ������ IP�ּ�
	// @ op: ARP OP Code
	void SetARPRequest(uint8_t *out, uint8_t *srcmac, uint8_t *srcip, uint8_t *dstmac, uint8_t *dstip, uint16_t op);
	
	// ICMP Send
	// ��¥, ������ �Լ� ��� ����
	void SendPingInWin(uint32_t dstip);
	// ���� ����, ������ ����
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

		// UDP ������ ����
		memset(data, 0, datalen);
		for (int i = 0; i < datalen; i++)
			data[i] = i + 0x44;
		
		uint32_t dstip = inet_addr("172.16.5.201");
		SetUDP(packet, nicinfo->NICIPAddress, dstip, 1300, 1300, data,  datalen);
		free(data);

		// IP ��� ����(-����ȭ ��� x-)
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

		// �̴��� ��� ����
		SetETHHeaderWithARP(packet, nicinfo->NICMACAddress, htons(ETHTYPE::IPV4), dstip);
		// ��Ŷ ����
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
	// ICMP �޽��� �ۼ�(üũ�� �ڵ�)
	void SetICMPV4Packet(
		uint8_t *out,
		uint8_t type, 
		uint8_t code, 
		uint16_t iden, 
		uint16_t seq, 
		uint8_t *data,
		uint16_t datalen);
	
	// �÷��� �ɼ� �ִ� ���� �ʿ�
	// ip �ɼ� �ִ� ���� �ʿ�

	// IP ��Ŷ �ۼ�
	// @ packet: ��Ŷ �ۼ��� ���� ��ġ
	// @ headerlen: ipv4 header length
	// @ identification:
	// @ flags: ����ȭ �÷���
	// @ ttl: Time Ti Live
	// @ prototype: �������� ����
	// @ ischeck: üũ�� ����, false�� ��� 0���� ����
	// @ *ip: ip
	// @ data: ip data ���� ��ġ
	// @ datalen: data ũ��
	// @ option: �ɼ� ���� ��ġ(�⺻ NULL)
	// @ optionlen: �ɼ� ����(�⺻ 0)
	void SetIPPacket(uint8_t *packet, uint16_t headerlen, uint16_t identification, uint16_t flags, uint8_t ttl, uint8_t prototype,
		bool ischeck, uint8_t *srcip, uint8_t *dstip, uint8_t *data, uint16_t datalen,uint8_t *option = NULL, uint16_t optionlen = 0);

	// �̴��� ��� ����
	// ARP Table�� ARP�� ����Ͽ� ��� ���ּ� ����
	// @ packet: ������ ���� ��ġ
	// @ src: �޽��� �۽��� �� �ּ�
	// @ prototype: �������� Ÿ��
	// @ dstip: ������ ip �ּ�
	int SetETHHeaderWithARP(uint8_t *packet, uint8_t *src, uint16_t prototype, uint32_t dstip);
	// ���� ����, ���� ������ �ּҸ� ������ �� ���
	void SetETHHeader(uint8_t *packet, uint8_t *dst, uint8_t *src, uint16_t prototype);
	
	// ARP ���̺� ��������
	// @ pmib: ������ ��ġ, ��� �� free(pmib) �ʿ�
	int GetARPTable(PMIB_IPNETTABLE *pmib);

	// ��Ʈ��ũ ������ �ּ����� Ȯ��
	// @ ip: Ȯ���� �ּ�
	bool IsInNet(uint32_t ip);

public:
	CWPcapSendSocket();
	virtual ~CWPcapSendSocket();
};

#endif	// _SENDSOCKET_H__ //