#ifndef _NICINFOLIST_H__
#define _NICINFOLIST_H__

#include <stdint.h>
#include <iostream>
#include <vector>
#include <list>
#include <memory>

#include "inetproto.h"

using std::string;
using std::vector;
using std::list;
using std::shared_ptr;

typedef struct NICInfo
{
	string Description;
	string AdapterName;
	uint32_t Netmask;
	uint32_t GatewayIPAddress;
	uint32_t NICIPAddress;
	uint8_t NICMACAddress[MACADDRESS_LENGTH];
	
	NICInfo()
	{
		Description.clear();
		AdapterName.clear();
		memset(NICMACAddress, 0, MACADDRESS_LENGTH);
	}
}NICInfo, *PNICInfo;

class CNICInfoList
{
private:
	typedef std::list< shared_ptr<NICInfo> >::iterator it_NICInfo;

	list< shared_ptr<NICInfo> > m_List;

public:
	CNICInfoList()
	{
		m_List.clear();
	}
	~CNICInfoList()	{ ClearList(); }

	void AddItem(shared_ptr<NICInfo>);
	void AddItem(const char *name, const char *des, uint32_t netmask, uint32_t gatewayip, uint32_t ip, const uint8_t *mac);
	int IsInItem(const char *name);
	void RemoveItem(shared_ptr<NICInfo> spNICInfo);
	void ClearList();
	// index´Â 0ºÎÅÍ, last item index == size - 1
	shared_ptr<NICInfo> At(int index);
	int GetSize();
};

#endif // _NICINFOLIST_H__