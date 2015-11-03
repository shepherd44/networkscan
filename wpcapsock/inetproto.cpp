#include "inetproto.h"

// Checksum
// ��� ���̴� ����Ʈ ����
uint16_t IPHeaderChecksum(uint16_t iph_len, uint16_t *piph)
{
	uint32_t sum = 0;

	// 2����Ʈ ������ ���ϹǷ� iph_len/2
	iph_len >>= 1;
	for (uint16_t i = 0; i<iph_len; i = i + 1)
		sum += ((piph[i] & 0xFF00) >> 8) + ((piph[i] & 0x00FF) << 8);
	// ĳ�� ó��
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	// 1�� ����
	sum = ~sum & 0xFFFF;

	return ((uint16_t)sum);
}

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
	)
{
	ARPPacket arppacket;
	memset(&arppacket, 0, sizeof(ARPPacket));
	int arplen = sizeof(ARPPacket);

	// arppacket �����
	arppacket.htype = htype;								// �ϵ���� Ÿ��
	arppacket.ptype = ptype;								// �������� Ÿ��
	arppacket.hlen = hlen;						// �ϵ���� �ּ� ����
	arppacket.plen = plen;					// �������� �ּ� ����
	arppacket.opcode = opcode;	// ARP OPCODE
	memcpy(arppacket.shaddr, srcmac, MACADDRESS_LENGTH);	// �۽��� �ϵ���� �ּ� ����
	memcpy(arppacket.spaddr, srcip, IPV4ADDRESS_LENGTH);	// �۽��� IP address ����
	memcpy(arppacket.dhaddr, dstmac, MACADDRESS_LENGTH);	// ������ �ϵ���� �ּ� ����
	memcpy(arppacket.dpaddr, dstip, IPV4ADDRESS_LENGTH);	// ������ ip address ����

	// ��Ŷ ����
	memcpy(out, &arppacket, arplen);
}