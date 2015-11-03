// �������� Ÿ�� ����
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
	// ��Ŷ ����
	int SendPacket(uint8_t *packet, int len);
	// ARP ��û �޽��� ����
	int SendARPRequest(uint32_t dstip);
	// ������ MAC �ּ� ���
	// ���� �� 0, ���� �� -1 ��ȯ
	int GetDstMAC(uint8_t *dstmac, uint32_t dstip);

	
	// ARP ��û �޽��� �ۼ�
	void SetARPRequest(uint8_t *out,
		uint8_t *srcmac,
		uint8_t *srcip,
		uint8_t *dstmac,
		uint8_t *dstip,
		uint16_t op);	
	
	// ICMP Send
	void SendPingInWin(uint32_t dstip);			// ��¥, ������ �Լ� ��� ����
	void SendICMPV4ECHORequest(uint32_t dstip);	// ���� ����, ������ ����

	// ICMP �޽��� �ۼ�
	void SetICMPV4Packet(
		uint8_t *out,
		uint8_t type, 
		uint8_t code, 
		uint16_t iden, 
		uint16_t seq, 
		uint8_t *data,
		uint16_t datalen);
	
	// IP ��Ŷ �ۼ�
	// �÷��� �ɼ� �ִ� ���� �ʿ�
	// ip �ɼ� �ִ� ���� �ʿ�
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

	// �̴��� ��� ����
	// ARP Table�� ARP�� ����Ͽ� ��� ���ּ� ����
	// �ۼ���
	int SetETHHeaderWithARP(
		uint8_t *packet,		// (out)��Ŷ ���� �ּ�
		uint8_t *src,			// �޼��� �۽��� �� �ּ�
		uint16_t prototype,		// �������� Ÿ��
		uint32_t dstip);		// ������ ip �ּ�
	void SetETHHeader(uint8_t *packet, uint8_t *dst, uint8_t *src, uint16_t prototype);			// ���� ����, ���� �̴����� ������ �� ���
	int GetARPTable(PMIB_IPNETTABLE *pmib);

	// ��Ʈ��ũ ������ �ּ����� Ȯ��
	// �׽�Ʈ �ʿ�
	bool IsInNet(uint32_t ip);

public:
	CWPcapSendSocket();
	virtual ~CWPcapSendSocket();
};

#endif	// _SENDSOCKET_H__ //