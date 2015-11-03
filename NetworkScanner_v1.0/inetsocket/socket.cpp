#include "socket.h"

// ������
CPcapSocket::CPcapSocket()
{
	SockInit();
}


CPcapSocket::~CPcapSocket()
{
	pcap_freealldevs(m_pNetDevice);
	pcap_close(m_pCapHandler);

}

// �ʱ�ȭ �Լ�
void CPcapSocket::SockInit()
{
	m_pCapHandler = NULL;
	m_pNetDevice = NULL;
	memset(m_ErrBuffer, '\0', sizeof(m_ErrBuffer));
	FindNetDevice();
	GetNICInfo();
	OpenNetDevice();
}

// �۵����� ��Ʈ��ũ ����̽� ã��
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

// ��Ʈ��ũ �������̽� ����
void CPcapSocket::OpenNetDevice()
{
	m_pCapHandler = pcap_open_live(m_pNetDevice->name, 65536, 1, 1000, m_ErrBuffer);
}

// ��Ʈ��ũ �������̽� ���� ���
// MAC, IP, NETMASK
void CPcapSocket::GetNICInfo()
{
	DWORD size = sizeof(PIP_ADAPTER_INFO);
	PIP_ADAPTER_INFO Info;
	ZeroMemory(&Info, size);

	// ��Ʈ��ũ �������̽� ���� ��������
	int result = GetAdaptersInfo(Info, &size);
	if (result == ERROR_BUFFER_OVERFLOW)
	{
		Info = (PIP_ADAPTER_INFO)malloc(size);
		GetAdaptersInfo(Info, &size);
	}

	// ��Ʈ��ũ �������̽� MAC �ּ�
	memcpy(m_MyMACAddress, Info->Address, 6);
	// ��Ʈ��ũ �������̽� IP �ּ�
	u_long ipaddr = inet_addr(Info->IpAddressList.IpAddress.String);
	memcpy(m_MyIPAddress, &ipaddr, 4);
	// ��Ʈ��ũ �������̽� Netmask
	u_long netmask = inet_addr(Info->IpAddressList.IpMask.String);
	memcpy(&m_Netmask, &netmask, 4);

	free(Info);
}