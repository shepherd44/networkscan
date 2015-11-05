#pragma once

#include "gtest\gtest.h"
#include "socket.h"
#include "sendsocket.h"
#include "capturesocket.h"
#include "NICInfoList.h"


class CWPcapSocketTest : public testing::Test
{
protected:
	// test 초기화
	virtual void SetUp()
	{
	}
	// test 소멸자
	virtual void TearDown()
	{
	}

	// test 공용 변수
	CWPcapSocket m_wpcapsock;
	CWPcapCaptureSocket m_capsock;
	CWPcapSendSocket m_sendsock;

public:
	CWPcapSocketTest();
	~CWPcapSocketTest();
};

//// NIC list test
//TEST(NICInfoListTest, ListTest)
//{
//	CNICInfoList niclist;
//	niclist.ClearList();
//	u_char mac[6] = {0,0,0,0,0,10};
//	ASSERT_EQ(0, niclist.GetSize());
//	
//	NICInfo *p = niclist.At(0);
//	ASSERT_EQ(NULL, (uint32_t)p);
//	
//	niclist.AddItem("21", "11", 11, 21, mac);
//	niclist.AddItem("22", "12", 12, 22, mac);
//	niclist.AddItem("23", "13", 13, 23, mac);
//	niclist.AddItem("24", "14", 14, 24, mac);
//	ASSERT_EQ(4, niclist.GetSize());
//
//	p = niclist.At(2);
//	ASSERT_EQ((uint32_t)13, p->Netmask);
//
//	niclist.RemoveItem(&p->list);
//	p = niclist.At(2);
//	ASSERT_EQ((uint32_t)14, p->Netmask);
//
//	niclist.ClearList();
//	ASSERT_EQ(0, niclist.m_ListSize);
//	ASSERT_EQ(&niclist.m_ListHead, niclist.m_ListHead.next);
//}
//
//// 최초 socket 생성 시
//TEST_F(CWPcapSocketTest, SocketEmptyInit)
//{
//	// 현재 
//	ASSERT_NE(0, m_wpcapsock.GetNicNumber());
//	
//	ASSERT_NE((u_long)NULL, (u_long)m_wpcapsock.m_pAllNIC);
//	ASSERT_EQ(NULL, m_wpcapsock.m_pCapHandler);
//}
//
//// 소켓 연결(Default 0번 열기)
//TEST_F(CWPcapSocketTest, SocketOpenNetDevice0)
//{
//	m_wpcapsock.OpenNetDevice();
//	
//	ASSERT_EQ(2, m_wpcapsock.GetNicNumber());
//
//	ASSERT_NE((u_long)NULL, (u_long)m_wpcapsock.m_pAllNIC);
//	ASSERT_NE((u_long)NULL, (u_long)m_wpcapsock.m_pCapHandler);
//}
//
//// 소켓 연결(1번 열기)
//TEST_F(CWPcapSocketTest, SocketOpenNetDevice1)
//{
//	m_wpcapsock.OpenNetDevice(1);
//	ASSERT_EQ(2, m_wpcapsock.GetNicNumber());
//
//	ASSERT_NE((u_long)NULL, (u_long)m_wpcapsock.m_pAllNIC);
//	ASSERT_NE((u_long)NULL, (u_long)m_wpcapsock.m_pCapHandler);
//}
//
//TEST_F(CWPcapSocketTest, CloseSocket)
//{
//	m_wpcapsock.OpenNetDevice(1);
//	m_wpcapsock.CloseNetDevice();
//	ASSERT_EQ((u_long)NULL, (u_long)m_wpcapsock.m_pAllNIC);
//	ASSERT_EQ((u_long)NULL, (u_long)m_wpcapsock.m_pCapHandler);
//
//}
//
//TEST_F(CWPcapSocketTest, SendSocket_GetDstMAC)
//{
//	m_sendsock.OpenNetDevice(0);
//	
//	uint8_t mac[6];
//	uint32_t ip = inet_addr("172.16.4.90");
//	int ret = m_sendsock.GetDstMAC(mac, ip);
//	ASSERT_EQ(0, ret);
//}
pcap_if_t* ChosenDevice;
TEST_F(CWPcapSocketTest, SendSocket_SetICMPV4ECHO)
{
	m_sendsock.OpenNetDevice(0);
	uint32_t dst = inet_addr("172.16.5.60");
	int ret = pcap_datalink(m_sendsock.m_pCapHandler);
	ASSERT_EQ(DLT_EN10MB, ret);
	//while (1)
	{
		//m_sendsock.SendUDP();
		m_sendsock.SendICMPV4ECHORequest(dst);
		m_sendsock.SendICMPV4ECHORequest(dst);
		m_sendsock.SendICMPV4ECHORequest(dst);
		m_sendsock.SendICMPV4ECHORequest(dst);
		m_sendsock.SendICMPV4ECHORequest(dst);
		//m_sendsock.SendPingInWin(dst);
		Sleep(1000);
	}
}

//void PrintPacket(const u_char *param, const u_char *pkt_data)
//{
//	(param);
//	ETHHeader *ethh = (ETHHeader *)pkt_data;
//	PIPV4Header iph;
//	printf("-------------------------------------------\n");
//	printf("dstMAC: %02X:%02X:%02X:%02X:%02X:%02X:\n", ethh->dstmac[0], ethh->dstmac[1], ethh->dstmac[2],
//		ethh->dstmac[3], ethh->dstmac[4], ethh->dstmac[5]);
//	printf("srcMAC: %02X:%02X:%02X:%02X:%02X:%02X:\n", ethh->srcmac[0], ethh->srcmac[1], ethh->srcmac[2],
//		ethh->srcmac[3], ethh->srcmac[4], ethh->srcmac[5]);
//
//	switch (ntohs(ethh->prototype))
//	{
//	case ETHTYPE::ARP:
//		printf("protocol type: ARP\n");
//		break;
//	case ETHTYPE::IPV4:
//		iph = (PIPV4Header)(pkt_data + ETHERNETHEADER_LENGTH);
//		printf("protocol type: IPV4\n");
//		printf("srcIP: %d.%d.%d.%d\n", iph->srcaddr[0], iph->srcaddr[1], iph->srcaddr[2], iph->srcaddr[3]);
//		printf("dstIP: %d.%d.%d.%d\n", iph->dstaddr[0], iph->dstaddr[1], iph->dstaddr[2], iph->dstaddr[3]);
//		switch (iph->protoid)
//		{
//		case IPV4TYPE::ICMP:
//			printf("ProtocolType: ICMP\n");
//			break;
//		case IPV4TYPE::TCP:
//			printf("ProtocolType: TCP\n");
//			break;
//		case IPV4TYPE::UDP:
//			printf("ProtocolType: UDP\n");
//			break;
//		default:
//			break;
//		}
//
//		break;
//	default:
//		printf("protocol type: OTHER\n");
//		break;
//	}
//}
//TEST_F(CWPcapSocketTest, SendSocket_Capture)
//{
//	m_capsock.OpenNetDevice(0);
//	m_capsock.CreatePacketFilter("");
//	m_capsock.StartCapture(PrintPacket, NULL, 0, 0);
//}