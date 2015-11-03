
// NetworkScanner_v1.0Dlg.h : ��� ����
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"

#include "NICInfoDlg.h"
#include "NetworkIPScan.h"
#include "IPStatusList.h"

// ����Ʈ ��Ʈ�� ���� ��ũ��
#if LIST_COLUMN_LENGTH
#undef LIST_COLUMN_LENGTH
#define LIST_COLUMN_LENGTH	120		// ����Ʈ ��Ʈ�� �÷� ����
#define LIST_COLUMN_NUMBER_LENGTH		40
#else if
#define LIST_COLUMN_LENGTH	120		// ����Ʈ ��Ʈ�� �÷� ����
#define LIST_COLUMN_NUMBER_LENGTH		40
#endif
// ����Ʈ ��Ʈ�� �÷� ��Ʈ�� ���� ��ũ��

#define LISTCTRL_COULMNSTRING	static wchar_t *ListCtrlColumnString[] = {	\
														_T("V"),			\
														_T("No"),			\
														_T("IP Address"),	\
														_T("MAC Address"),	\
														_T("IP Status"),	\
														_T("PING Reply"),	\
													}
// IPSTATUSINFO �� ���� ���� ��ũ��
// IPSTATUS ������ �������
#define IPSTATUS_CELLCOLOR	static COLORREF ipstatcolor[] =	{				\
														RGB(255, 255, 255),	\
														RGB(250, 250, 210),	\
														RGB(0, 200, 0),		\
														RGB(200, 0, 0),		\
														RGB(0, 0, 255)		\
													}
// �������ͽ��� ��Ʈ�� ���� ��ũ��

// ��ư Ŭ�� ���� ó���� enum
enum SCANNIG_STATE
{
	BEGIN = 0,	// 0, ó�� ���۽�
	SCANNIG,	// 1, ��ĵ ���� ��
	STOP_ALL,	// 4, ��Ŷ ����, ĸó ��� ����
	STOP_SEND,	// 2, IP ���� Ȯ�ο� ��Ŷ ���� ����
	STOP_RECV,	// 3, ��Ŷ ĸó �� �м� ����

	SCANNING_STATE_END	// END
};

// CNetworkScannerDlg ��ȭ ����
class CNetworkScannerDlg : public CDialogEx
{
// �����Դϴ�.
public:
	CNetworkScannerDlg(CWnd* pParent = NULL);	// ǥ�� �������Դϴ�.

// ��ȭ ���� �������Դϴ�.
	enum { IDD = IDD_NETWORKSCANNER_V10_DIALOG };

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
	DECLARE_MESSAGE_MAP()

protected:
	void InitializeAll();

	CEvent m_EventListUpdate;
	CWinThread *m_ListUpdateThread;
	bool m_IsListUpdateThreadDye;
	
	void StartListUpdateThread();
	void EndListUpdateThread();
	static UINT AFX_CDECL ListUpdateThreadFunc(LPVOID lpParam);

// ��Ʈ�� ���� �� �Լ�
public:
	// ��ư Ŭ�� �̺�Ʈ ó��
	afx_msg void OnBnClickedBtnScan();			// ��ĵ ���� ��ư
	afx_msg void OnBnClickedBtnStopAll();		// ��ĵ ����
	afx_msg void OnBnClickedBtnStopSend();		// ��Ŷ ���� ����
	afx_msg void OnBnClickedBtnStopRecv();		// ��Ŷ ĸó ����
	afx_msg void OnBnClickedBtnNicdetail();		// NIC ���� �ڼ��� ����
	afx_msg void OnBnClickedBtnScanAddip();
	afx_msg void OnBnClickedBtnScanRemoveip();

	// ����Ʈ ��Ʈ�� ���� �� �Լ�
	CListCtrl m_ListCtrlScanResult;
	afx_msg void OnListIPStatusCustomdraw(NMHDR* pNMHDR, LRESULT* pResult);
	void ListCtrlInit();
	void ListCtrlDeleteAll();
	void ListCtrlInsertData(IPStatusInfo *item);
	int *GetCheckedItem();
	bool IsListUpdateThreadDye() { return m_IsListUpdateThreadDye; }
	void ListCtrlUpdate(){ m_EventListUpdate.SetEvent(); }

	// ������ �Է� ��Ʈ�� ���� �� �Լ�
	CIPAddressCtrl m_IPAddrCtrlBeginIP;
	CIPAddressCtrl m_IPAddrCtrlEndIP;
	void IPAddrCtrlInit();

	// �������ͽ��� ��Ʈ�� ���� �� �Լ�
	CStatusBarCtrl m_StatusBarCtrl;
	void StatusBarCtrlInit();
	void StatusBarCtrlUpdate(int index, wchar_t* string);

	// üũ�ڽ� ��Ʈ�� ���� �� �Լ�
	CButton m_CheckBoxCtrlIsHideDeadIP;		// HideDeadIP
	
	// ��ĳ�� Ŭ����
	CNetworkIPScan m_NetworkIPScan;

	// NICInfoDlg
	CNICInfoDlg m_NICInfoDlg;
	CComboBox m_ComboCtrlNICInfo;
	// NIC ���ÿ� �޺� �ڽ�
	void ComboBoxInit();

	afx_msg void OnClose();
};
