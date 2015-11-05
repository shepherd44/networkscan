
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

#define LISTCTRL_COULMNSTRING__	static wchar_t *ListCtrlColumnString[] = {	\
														_T("V"),			\
														_T("No"),			\
														_T("IP Address"),	\
														_T("MAC Address"),	\
														_T("IP Status"),	\
														_T("PING Reply"),	\
													}
#define LISTCTRL_COULMNSTRING_			ListCtrlColumnString
#define LISTCTRL_COULMNSTRING(index)	ListCtrlColumnString[index]

// IPSTATUSINFO �� ���� ���� ��ũ��
// IPSTATUS ������ �������
#define IPSTATUS_CELLCOLOR__	static COLORREF ipstatcolor[] =	{				\
														RGB(255, 255, 255),	\
														RGB(250, 250, 210),	\
														RGB(0, 200, 0),		\
														RGB(200, 0, 0),		\
														RGB(0, 0, 255)		\
													}
#define IPSTATUS_CELLCOLOR(index)	ipstatcolor[index]

// �������ͽ��� ��Ʈ�� ���� ��ũ��
// SCANNING_STATE ������� ����
#define STATUSBARCTRL_STRING__	static wchar_t *statusbarstring[] = {		\
	_T("Program start. Scannig Available"),									\
	_T("Scan start. Sending Packet."),										\
	_T("Scan start. Sending ARP Packet."),									\
	_T("Scan start. Sending ICMP Packet."),									\
	_T("Stop scannig"),														\
	_T("Stop send packet"),													\
	_T("Stop captue packet"),												\
	_T("Program End. Wait...")												\
};
#define STATUSBARCTRL_STRING(index)		statusbarstring[index]
// ��ư Ŭ�� ���� ó���� enum
enum SCANNIG_STATE
{
	BEGIN = 0,			// 0, ó�� ���۽�
	SCANNIG,			// 1, ��ĵ ���� ��
	SCANNING_ARPSEND,	// 2, ARP ��Ŷ ���� 
	SCANNING_PINGSEND,	// 3, ICMP ��Ŷ ����
	STOP_ALL,			// 4, ��Ŷ ����, ĸó ��� ����
	STOP_SEND,			// 5, IP ���� Ȯ�ο� ��Ŷ ���� ����
	STOP_RECV,			// 6, ��Ŷ ĸó �� �м� ����
	PROGRAM_END,		// 7, ���α׷� ������
	
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

	// ����Ʈ ��Ʈ�� ������Ʈ ���� �̺�Ʈ ����
	CEvent *m_EventListUpdate;
	// ����Ʈ ��Ʈ�� ������Ʈ ������
	CWinThread *m_ListUpdateThread;
	// ����Ʈ ��Ʈ�� ������ ����
	bool m_IsListUpdateThreadDye;

	// ����Ʈ ��Ʈ�� ������Ʈ ������ ����
	void StartListUpdateThread();
	// ����Ʈ ��Ʈ�� ������Ʈ ������ ����
	void EndListUpdateThread();
	// ����Ʈ ��Ʈ�� �����̵� ������ �Լ�
	static UINT AFX_CDECL ListUpdateThreadFunc(LPVOID lpParam);

	// ���α׷� ����
	SCANNIG_STATE m_ProgramState;

// ��Ʈ�� ���� �� �Լ�
public:
	// ��ư Ŭ�� �̺�Ʈ ó��
	afx_msg void OnBnClickedBtnScan();			// ��ĵ ���� ��ư
	afx_msg void OnBnClickedBtnStopAll();		// ��ĵ ����
	afx_msg void OnBnClickedBtnStopSend();		// ��Ŷ ���� ����
	afx_msg void OnBnClickedBtnStopRecv();		// ��Ŷ ĸó ����
	afx_msg void OnBnClickedBtnNicdetail();		// NIC ���� �ڼ��� ����
	afx_msg void OnBnClickedBtnScanAddip();		// IP �߰�
	afx_msg void OnBnClickedBtnScanRemoveip();	// IP ����

	// ����Ʈ ��Ʈ�� ���� �� �Լ�
	CListCtrl m_ListCtrlScanResult;
	// ����Ʈ ��Ʈ�� ���� ���� ���� �Լ�
	afx_msg void OnListIPStatusCustomdraw(NMHDR* pNMHDR, LRESULT* pResult);
	// ����Ʈ ��Ʈ�� �ʱ�ȭ �Լ�
	void ListCtrlInit();
	// ����Ʈ ��Ʈ�� ����
	void ListCtrlDeleteAll();
	// ����Ʈ ��Ʈ�� ���� ��� ���ۿ��� ������Ʈ
	void ListCtrlDeleteAndInsert();
	// ����Ʈ ��Ʈ�ѿ� ������ ����(Tail)
	void ListCtrlInsertData(IPStatusInfo *item);
	// ����Ʈ ��Ʈ�� �׸� ���� �Լ�
	void ListCtrlUpdateData(int index, IPStatusInfo *item);
	// üũ�ڽ��� üũ�� �׸� ��������
	int *GetCheckedItem();
	// ����Ʈ ��Ʈ�� ������Ʈ 
	bool IsListUpdateThreadDye() { return m_IsListUpdateThreadDye; }
	// ����Ʈ ��Ʈ�� ������Ʈ ����(�̺�Ʈ �ñ׳� �߻�)
	void ListCtrlUpdate(){ m_EventListUpdate->SetEvent(); }

	// ������ �Է� ��Ʈ�� ���� �� �Լ�
	CIPAddressCtrl m_IPAddrCtrlBeginIP;
	CIPAddressCtrl m_IPAddrCtrlEndIP;
	// ������ �Է� ��Ʈ�� �ʱ�ȭ
	void IPAddrCtrlInit();

	// �������ͽ��� ��Ʈ�� ���� �� �Լ�
	CStatusBarCtrl m_StatusBarCtrl;
	// �������ͽ��� ��Ʈ�� �ʱ�ȭ
	void StatusBarCtrlInit();
	// �������ͽ��� ��Ʈ�� ������Ʈ
	void StatusBarCtrlUpdate();
	void StatusBarCtrlUpdate(wchar_t* string);

	// üũ�ڽ� ��Ʈ�� ���� �� �Լ�
	CButton m_CheckBoxCtrlIsHideDeadIP;		// HideDeadIP
	
	// ��ĳ�� Ŭ����
	CNetworkIPScan m_NetworkIPScan;

	// NICInfoDlg
	CNICInfoDlg m_NICInfoDlg;
	CComboBox m_ComboCtrlNICInfo;
	// NIC ���ÿ� �޺� �ڽ�
	void ComboBoxInit();

	// ���α׷� ���� Ȯ��
	void SetProgramState(SCANNIG_STATE state) { m_ProgramState = state; }
	int GetProgeamState() { return m_ProgramState; }
	afx_msg void OnClose();
};
