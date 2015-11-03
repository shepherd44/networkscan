
// IPScannerDlg.h : ��� ����
//

#pragma once
#include "afxcmn.h"
 
#include "NetworkIPScan.h"

// CIPScannerDlg ��ȭ ����
class CIPScannerDlg : public CDialogEx
{
// �����Դϴ�.
public:
	CIPScannerDlg(CWnd* pParent = NULL);	// ǥ�� �������Դϴ�.

// ��ȭ ���� �������Դϴ�.
	enum { IDD = IDD_IPSCANNER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV �����Դϴ�.


// �����Դϴ�.
protected:
	HICON m_hIcon;

	// ������ �޽��� �� �Լ�
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	// ��ư Ŭ�� �̺�Ʈ ó��
	afx_msg void OnBnClickedBtnScan();
	// ����Ʈ ��Ʈ�� ���� ó��
	afx_msg void OnListIPStatusCustomdraw(NMHDR* pNMHDR, LRESULT* pResult);
	DECLARE_MESSAGE_MAP()

// ��� ����
protected:
	// IP ���� ��ĵ Ŭ����
	CNetworkIPScan m_networkIPScanner;

private:
	// �ʱ�ȭ �Լ�
	void InitializeAll();		// ��ü �ʱ�ȭ
	void ListCtrlInit();		// ����Ʈ ��Ʈ�� �ʱ�ȭ
	void IPAddressCtrlInit();	// IP�ּ� ��Ʈ�� �ʱ�ȭ
	
public:
	// ����Ʈ ��Ʈ�� ����
	CListCtrl m_ListIPStatus;

	// IPAddress �Է� ��Ʈ��
	CIPAddressCtrl m_IPAddressBeginIP;
	CIPAddressCtrl m_IPAddressEndIP;
	
public:
	// ����Ʈ ��Ʈ�� ���� �Լ�
	void ListCtrlInsertData(IPStatusInfo *ipstat);
	void ListCtrlDeleteAll();
	void Display();
};

