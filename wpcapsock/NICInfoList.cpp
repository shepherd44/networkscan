#include "NICInfoList.h"

void CNICInfoList::AddItem(shared_ptr<NICInfo> spNICInfo)
{
	m_List.push_back(spNICInfo);
}

void CNICInfoList::AddItem(const char *name, const char *des, uint32_t netmask, uint32_t gatewayip, uint32_t ip, const uint8_t *mac)
{
	shared_ptr<NICInfo> temp(new NICInfo);
	// 리스트에 삽입
	m_List.push_back(temp);
	
	// 값 셋팅
	temp->AdapterName = name;
	temp->Description = des;
	temp->Netmask = netmask;
	temp->GatewayIPAddress = gatewayip;
	temp->NICIPAddress = ip;
	memcpy(temp->NICMACAddress, mac, MACADDRESS_LENGTH);
}

int CNICInfoList::IsInItem(const char *name)
{
	int ret = 0;

	it_NICInfo bi, ei;
	bi = m_List.begin();
	ei = m_List.end();

	shared_ptr<NICInfo> item;
	for (; bi != ei; bi++)
	{
		item = *bi;
		if (strcmp(item->AdapterName.data(), name) == 0)
			return ret;
		ret++;
	}
	return -1;
}

void CNICInfoList::RemoveItem(shared_ptr<NICInfo> spNICInfo)
{
	it_NICInfo bi, ei;
	bi = m_List.begin();
	ei = m_List.end();
	
	shared_ptr<NICInfo> item;
	for (; bi != ei; bi++)
	{
		item = *bi;
		if (strcmp(item->AdapterName.data(), spNICInfo->AdapterName.data()) == 0)
		{
			m_List.erase(bi);
			bi = m_List.begin();
			ei = m_List.end();
		}
	}
}

void CNICInfoList::ClearList()
{
	m_List.clear();
}

// index는 0부터, last item index == size - 1
shared_ptr<NICInfo> CNICInfoList::At(int index)
{
	if (index >= (int)m_List.size())
		return nullptr;
	it_NICInfo bi;
	bi = m_List.begin();
	
	shared_ptr<NICInfo> item;
	for (int i = 0; i < index; i++)
	{
		bi++;
	}
	item = *bi;
	return item;
}

int CNICInfoList::GetSize()
{
	return m_List.size();
}