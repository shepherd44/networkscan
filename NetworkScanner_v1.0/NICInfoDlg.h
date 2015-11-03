#pragma once
#include "afxcmn.h"

// ����Ʈ ��Ʈ�� �÷� ����
#if LIST_COLUMN_LENGTH
#undef LIST_COLUMN_LENGTH
#undef LIST_COLUMN_NUMBER_LENGTH
#define LIST_COLUMN_LENGTH	100
#define	LIST_COLUMN_NUMBER_LENGTH	40
#else if
#define LIST_COLUMN_LENGTH	100
#define	LIST_COLUMN_NUMBER_LENGTH	40
#endif

// ����Ʈ ��Ʈ�� �÷� ��Ʈ�� ���� ��ũ��
#define LISTCTRLNICINFO_COULMNSTRING	static wchar_t *ListCtrlColumnString[] = {	\
																_T("No"),			\
																_T("NIC Name"),		\
																_T("IP Address"),	\
																_T("MAC Address"),	\
																_T("Netmask")		\
																}

// CNICInfoDlg ��ȭ �����Դϴ�.

class CNICInfoDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CNICInfoDlg)

public:
	CNICInfoDlg(CWnd* pParent = NULL);   // ǥ�� �������Դϴ�.
	virtual ~CNICInfoDlg();

// ��ȭ ���� �������Դϴ�.
	enum { IDD = IDD_DIALOG_NICINFO };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV �����Դϴ�.

	DECLARE_MESSAGE_MAP()

protected:
public:
	// ��Ʈ�� �Լ� �� ����
	afx_msg void OnBnClickedBtnSelect();
	afx_msg void OnBnClickedCancel();

	virtual BOOL OnInitDialog();

	// ����Ʈ ��Ʈ��
	CListCtrl m_ListCtrlNICInfoList;
	void ListCtrlNICInfoInit();
	
	void InitializeAll();
	
};
