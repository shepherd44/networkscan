
// NetworkScanner_v1.0.h : PROJECT_NAME ���� ���α׷��� ���� �� ��� �����Դϴ�.
//

#pragma once

#ifndef __AFXWIN_H__
	#error "PCH�� ���� �� ������ �����ϱ� ���� 'stdafx.h'�� �����մϴ�."
#endif

#include "resource.h"		// �� ��ȣ�Դϴ�.


// CNetworkScannerApp:
// �� Ŭ������ ������ ���ؼ��� NetworkScanner_v1.0.cpp�� �����Ͻʽÿ�.
//

class CNetworkScannerApp : public CWinApp
{
public:
	CNetworkScannerApp();

// �������Դϴ�.
public:
	virtual BOOL InitInstance();

// �����Դϴ�.

	DECLARE_MESSAGE_MAP()
};

extern CNetworkScannerApp theApp;