#ifndef _NICINFOLIST_H__
#define _NICINFOLIST_H__

#include <stdint.h>
#include <iostream>
#include "inetproto.h"
#include "linkedlist.h"

typedef struct NICInfo
{
	char* Description;
	char* AdapterName;
	uint32_t Netmask;
	uint32_t NICIPAddress;
	uint8_t NICMACAddress[6];
	ListHead list;
}NICInfo, *PNICInfo;

class CNICInfoList
{
#ifdef _DEBUG
public:
#else
private:
#endif // _DEBUG
	ListHead m_ListHead;
	int m_ListSize;
public:
	CNICInfoList() : m_ListSize(0)
	{
		m_ListHead = LIST_HEAD_INIT(m_ListHead);
	}
	~CNICInfoList()	{ ClearList(); }

	void AddItem(const char *name, const char *des, uint32_t netmask, uint32_t ip, const uint8_t *mac);
	int IsInItem(const char *name);
	void RemoveItem(PListHead ph);
	void ClearList();
	// index´Â 0ºÎÅÍ, last item index == size - 1
	NICInfo* At(int index);
	int GetSize() { return m_ListSize; }
};

#endif // _NICINFOLIST_H__