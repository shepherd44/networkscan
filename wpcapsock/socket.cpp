#include "socket.h"

// 생성자
CWPcapSocket::CWPcapSocket()
{
	SockInit();
}

CWPcapSocket::~CWPcapSocket()
{
	m_NICInfoList.ClearList();
	CloseNetDevice();
}

// 초기화 함수
void CWPcapSocket::SockInit()
{
	m_CurSel = -1;
	m_pAllNIC = NULL;
	m_pCapHandler = NULL;
	memset(m_ErrBuffer, '\0', sizeof(m_ErrBuffer));

	//FindNetDevice();
}

// 작동중인 네트워크 디바이스 찾고 NICInfo에 채워넣기
void CWPcapSocket::FindNetDevice()
{
	if (pcap_findalldevs(&m_pAllNIC, m_ErrBuffer) == -1)
		throw WPcapSocketException("DeviceFindError\n");
	
	// 네트워크 디바이스 정보 얻기
	DWORD size = sizeof(PIP_ADAPTER_INFO);
	PIP_ADAPTER_INFO Info;
	ZeroMemory(&Info, size);

	// 네트워크 인터페이스 정보 가져오기
	int result = GetAdaptersInfo(Info, &size);
	if (result == ERROR_BUFFER_OVERFLOW) {
		Info = (PIP_ADAPTER_INFO)malloc(size);
		GetAdaptersInfo(Info, &size);
	}

	// NICInfoList 채우기
	m_NICInfoList.ClearList();
	for (pcap_if_t *d = m_pAllNIC; d; d = d->next)	{
		for (PIP_ADAPTER_INFO pai = Info; pai; pai = pai->Next)	{
			if (strcmp((d->name + NICNAME_OFFSET), pai->AdapterName) == 0)	{
				uint8_t mac[6];
				memset(mac, 0, MACADDRESS_LENGTH);
				memcpy(mac, pai->Address, MACADDRESS_LENGTH);
				m_NICInfoList.AddItem(d->name,
									  d->description,
									  inet_addr(pai->IpAddressList.IpMask.String), 
									  inet_addr(pai->GatewayList.IpAddress.String),
									  inet_addr(pai->IpAddressList.IpAddress.String), 
									  mac);
			}
			else
				continue;
		}
	}
	free(Info);
	if (m_NICInfoList.GetSize() == 0)
		throw WPcapSocketException("No Network Interface Found\n");
}

// 네트워크 인터페이스 연결(0부터 시작)
void CWPcapSocket::OpenNetDevice(int index)
{
	if (m_pAllNIC == NULL)
		FindNetDevice();
	if (index >= m_NICInfoList.GetSize())
		throw WPcapSocketException("index is over NIC Number");
	else
	{
		m_CurSel = index; 
		NICInfo *p = m_NICInfoList.At(index);
		m_pCapHandler = pcap_open_live(m_NICInfoList.At(index)->AdapterName, PACKET_SNAP_LEN, 1, -1, m_ErrBuffer);
	}
}
void CWPcapSocket::OpenNetDevice(const char *nicname)
{
	if (m_pAllNIC == NULL)
		FindNetDevice(); 
	int index = m_NICInfoList.IsInItem(nicname);
	if (index == -1)
		throw WPcapSocketException("Wrong NIC name");
	else
	{
		m_CurSel = index;
		m_pCapHandler = pcap_open_live(m_NICInfoList.At(index)->AdapterName, PACKET_SNAP_LEN, 1, 1000, m_ErrBuffer);
		if (m_pCapHandler == NULL)
			throw WPcapSocketException("pcap open error");
	}
	
	
}

void CWPcapSocket::CloseNetDevice()
{
	m_CurSel = -1;
	if (m_pAllNIC != NULL)
	{
		pcap_freealldevs(m_pAllNIC);
		m_NICInfoList.ClearList();
		m_pAllNIC = NULL;
	}
	
	if (m_pCapHandler != NULL)
	{
		pcap_close(m_pCapHandler);
		m_pCapHandler = NULL;
	}
}

int CWPcapSocket::GetNicNumber() { return m_NICInfoList.GetSize(); }
const char* CWPcapSocket::GetErrorBuffer() { return m_ErrBuffer; }
int CWPcapSocket::GetCurrentSelectNICNum() { return m_CurSel; }
const NICInfo* CWPcapSocket::GetCurrentSelectNICInfo() { return m_NICInfoList.At(m_CurSel); }
char *CWPcapSocket::GetCurrentSelectNICName()
{
	if (m_CurSel == -1)
		return NULL;
	else
		return m_NICInfoList.At(m_CurSel)->AdapterName;
}

CNICInfoList *CWPcapSocket::GetNICInfoList()
{
	return &m_NICInfoList;
}