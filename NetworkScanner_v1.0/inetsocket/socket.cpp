#include "socket.h"

// 생성자
CPcapSocket::CPcapSocket()
{
	SockInit();
}


CPcapSocket::~CPcapSocket()
{
	pcap_freealldevs(m_pNetDevice);
	pcap_close(m_pCapHandler);

}

// 초기화 함수
void CPcapSocket::SockInit()
{
	m_pCapHandler = NULL;
	m_pNetDevice = NULL;
	memset(m_ErrBuffer, '\0', sizeof(m_ErrBuffer));
	FindNetDevice();
	GetNICInfo();
	OpenNetDevice();
}

// 작동중인 네트워크 디바이스 찾기
void CPcapSocket::FindNetDevice()
{
	if (pcap_findalldevs(&m_pNetDevice, m_ErrBuffer) == -1)
	{
		throw std::exception("DeviceFindError\n");
	}
	int i = 0;
	for (pcap_if_t *d = m_pNetDevice; d; d = d->next)
		i++;
	if (i == 0)
		throw std::exception("No Network Interface Found\n");
}

// 네트워크 인터페이스 연결
void CPcapSocket::OpenNetDevice()
{
	m_pCapHandler = pcap_open_live(m_pNetDevice->name, 65536, 1, 1000, m_ErrBuffer);
}

// 네트워크 인터페이스 정보 얻기
// MAC, IP, NETMASK
void CPcapSocket::GetNICInfo()
{
	DWORD size = sizeof(PIP_ADAPTER_INFO);
	PIP_ADAPTER_INFO Info;
	ZeroMemory(&Info, size);

	// 네트워크 인터페이스 정보 가져오기
	int result = GetAdaptersInfo(Info, &size);
	if (result == ERROR_BUFFER_OVERFLOW)
	{
		Info = (PIP_ADAPTER_INFO)malloc(size);
		GetAdaptersInfo(Info, &size);
	}

	// 네트워크 인터페이스 MAC 주소
	memcpy(m_MyMACAddress, Info->Address, 6);
	// 네트워크 인터페이스 IP 주소
	u_long ipaddr = inet_addr(Info->IpAddressList.IpAddress.String);
	memcpy(m_MyIPAddress, &ipaddr, 4);
	// 네트워크 인터페이스 Netmask
	u_long netmask = inet_addr(Info->IpAddressList.IpMask.String);
	memcpy(&m_Netmask, &netmask, 4);

	free(Info);
}