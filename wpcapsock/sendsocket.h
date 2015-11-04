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
	int GetDstMAC(uint8_t *dstmac, uint32_t dstip, int timeout);

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