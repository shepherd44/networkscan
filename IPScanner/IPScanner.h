
// IPScanner.h : PROJECT_NAME ���� ���α׷��� ���� �� ��� �����Դϴ�.
//

#pragma once

#ifndef __AFXWIN_H__
	#error "PCH�� ���� �� ������ �����ϱ� ���� 'stdafx.h'�� �����մϴ�."
#endif

#include "resource.h"		// �� ��ȣ�Դϴ�.

#define _WINSOCK_DEPRECATED_NO_WARNINGS 1

// CIPScannerApp:
// �� Ŭ������ ������ ���ؼ��� IPScanner.cpp�� �����Ͻʽÿ�.
//

class CIPScannerApp : public CWinApp
{
public:
	CIPScannerApp();

// �������Դϴ�.
public:
	virtual BOOL InitInstance();

// �����Դϴ�.

	DECLARE_MESSAGE_MAP()
};

extern CIPScannerApp theApp;