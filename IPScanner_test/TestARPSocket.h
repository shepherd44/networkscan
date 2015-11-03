#pragma once

#include <vector>
#include <list>

#include "gtest\gtest.h"
#include "../IPScanner/ARPSocket.h"

class CTestARPSocket : public testing::Test
{
protected:
	// test �ʱ�ȭ
	virtual void SetUp()
	{
	}
	// test �Ҹ���
	virtual void TearDown()
	{
	}

	// test ���� ����
	CARPSocket m_TestARPSocket;

public:
	CTestARPSocket();
	~CTestARPSocket();
	
	void SendARP(u_long beginip, u_long endip);			// ���� ���� ARP ��Ŷ ������
	void StartCaptureThread();							// ARP ��Ŷ ĸ�� ������ ����
	static DWORD WINAPI CaptueThread(LPVOID lpParam);	// ARP ĸ�� ������ �Լ�
	void Analyze();										// ĸ�� ��� �м�
};

//using namespace std;

TEST_F(CTestARPSocket, Ttest)
{
	u_int a = UINT_MAX;
	u_int b = UINT_MAX - 10;
	while (1)
	{
		std::cout << a << " " << static_cast<int>(a) << std::endl;
		std::cout << a + 1 << " " << static_cast<int>(a + 1) << std::endl;
		std::cout << a - 1 << " " << static_cast<int>(a - 1) << std::endl;
		std::cout << a - b << " " << static_cast<int>(a - b) << std::endl;
		std::cout << b - a << " " << static_cast<int>(b - a) << std::endl;
		std::cout << b + a << " " << static_cast<int>(b + a) << std::endl;
	}
	
}

TEST_F(CTestARPSocket, Send_OneARPPacket)
{
	ASSERT_EQ(0, m_TestARPSocket.SendPacket(inet_addr("172.16.5.215")));
}

TEST_F(CTestARPSocket, Send_OneGARPPacket)
{
	ASSERT_EQ(0, m_TestARPSocket.SendPacket(inet_addr("0.0.0.0"), inet_addr("172.16.5.60")));
	ASSERT_EQ(0, m_TestARPSocket.SendPacket(inet_addr("172.16.5.60"), inet_addr("172.16.5.60")));
	ASSERT_EQ(0, m_TestARPSocket.SendPacket(inet_addr("172.16.5.60")));
}

TEST_F(CTestARPSocket, ARPSend_MultipleARPPacket)
{
	u_long ip = inet_addr("172.16.4.95");
	u_long rip = ntohl(ip);
	u_long endip = inet_addr("172.16.4.105");
	int i = 0;
	for (; rip <= ntohl(endip); rip++, i++)
		ASSERT_EQ(0, m_TestARPSocket.SendPacket(htonl(rip)));
}

TEST_F(CTestARPSocket, ARPSend_TimeCheck_254packet)
{
	SendARP(inet_addr("172.16.4.0"), inet_addr("172.16.4.254"));
}

TEST_F(CTestARPSocket, ARPCapture_10packet)
{
	m_TestARPSocket.StartCapture(10);
	ASSERT_EQ(10, m_TestARPSocket.GetCaptureListLength());
}

TEST_F(CTestARPSocket, ARPCapture_Thread_1sec)
{
	StartCaptureThread();
	Sleep(1000);
	m_TestARPSocket.EndCapture();
}

TEST_F(CTestARPSocket, ARPSendANDCaptureThread)
{
	StartCaptureThread();
	SendARP(inet_addr("172.16.4.1"), inet_addr("172.16.4.254"));
	Sleep(1000);
	m_TestARPSocket.EndCapture();
}

