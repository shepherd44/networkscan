#include "TestARPSocket.h"


CTestARPSocket::CTestARPSocket()
{
}


CTestARPSocket::~CTestARPSocket()
{
}

// ���� ���� ARP ��Ŷ ������
void CTestARPSocket::SendARP(u_long beginip, u_long endip)
{
	u_long ip = beginip;
	u_long rip = ntohl(ip);
	u_long end_ip = endip;
	int i = 0;
	for (; rip <= ntohl(end_ip); rip++, i++)
		m_TestARPSocket.SendPacket(htonl(rip));
}

// ARP ��Ŷ ĸ�� ������ ����
void CTestARPSocket::StartCaptureThread()
{
	HANDLE hCaptureThread = CreateThread(NULL,				// default security attributes 
										 0,					// use default stack size   
										 CaptueThread,		// thread function name 
										 &m_TestARPSocket, // argument to thread function  
										 0,					// use default creation flags  
										 NULL);				// returns the thread identifier  
	if (hCaptureThread == NULL)
		FAIL();
}

// ARP ĸ�� ������ �Լ�
DWORD WINAPI CTestARPSocket::CaptueThread(LPVOID lpParam)
{
	CARPSocket *arpsock = (CARPSocket *)lpParam;
	arpsock->StartCapture();
	return 0;
}

// ĸ�� ��� �м�
void CTestARPSocket::Analyze()
{
	std::list<ARPPacket>::iterator bli = m_TestARPSocket.GetCaptureListBegin();
	std::list<ARPPacket>::iterator eli = m_TestARPSocket.GetCaptureListEnd();
	int i = 0;
	for (; bli != eli; bli++, i++);
		//if (bli->)
}