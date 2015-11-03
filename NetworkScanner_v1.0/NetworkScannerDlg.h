
// NetworkScanner_v1.0Dlg.h : 헤더 파일
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"

#include "NICInfoDlg.h"
#include "NetworkIPScan.h"
#include "IPStatusList.h"

// 리스트 컨트롤 관련 매크로
#if LIST_COLUMN_LENGTH
#undef LIST_COLUMN_LENGTH
#define LIST_COLUMN_LENGTH	120		// 리스트 컨트롤 컬럼 길이
#define LIST_COLUMN_NUMBER_LENGTH		40
#else if
#define LIST_COLUMN_LENGTH	120		// 리스트 컨트롤 컬럼 길이
#define LIST_COLUMN_NUMBER_LENGTH		40
#endif
// 리스트 컨트롤 컬럼 스트링 선언 매크로

#define LISTCTRL_COULMNSTRING	static wchar_t *ListCtrlColumnString[] = {	\
														_T("V"),			\
														_T("No"),			\
														_T("IP Address"),	\
														_T("MAC Address"),	\
														_T("IP Status"),	\
														_T("PING Reply"),	\
													}
// IPSTATUSINFO 셀 배경색 선언 매크로
// IPSTATUS 열거형 순서대로
#define IPSTATUS_CELLCOLOR	static COLORREF ipstatcolor[] =	{				\
														RGB(255, 255, 255),	\
														RGB(250, 250, 210),	\
														RGB(0, 200, 0),		\
														RGB(200, 0, 0),		\
														RGB(0, 0, 255)		\
													}
// 스테이터스바 컨트롤 관련 매크로

// 버튼 클릭 상태 처리용 enum
enum SCANNIG_STATE
{
	BEGIN = 0,	// 0, 처음 시작시
	SCANNIG,	// 1, 스캔 시작 시
	STOP_ALL,	// 4, 패킷 전송, 캡처 모두 중지
	STOP_SEND,	// 2, IP 상태 확인용 패킷 전송 중지
	STOP_RECV,	// 3, 패킷 캡처 및 분석 중지

	SCANNING_STATE_END	// END
};

// CNetworkScannerDlg 대화 상자
class CNetworkScannerDlg : public CDialogEx
{
// 생성입니다.
public:
	CNetworkScannerDlg(CWnd* pParent = NULL);	// 표준 생성자입니다.

// 대화 상자 데이터입니다.
	enum { IDD = IDD_NETWORKSCANNER_V10_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 지원입니다.

// 구현입니다.
protected:
	HICON m_hIcon;

	// 생성된 메시지 맵 함수
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

// 컨트롤 변수 및 함수
public:
	// 버튼 클릭 이벤트 처리
	afx_msg void OnBnClickedBtnScan();			// 스캔 시작 버튼
	afx_msg void OnBnClickedBtnStopAll();		// 스캔 중지
	afx_msg void OnBnClickedBtnStopSend();		// 패킷 전송 중지
	afx_msg void OnBnClickedBtnStopRecv();		// 패킷 캡처 중지
	afx_msg void OnBnClickedBtnNicdetail();		// NIC 정보 자세히 보기
	afx_msg void OnBnClickedBtnScanAddip();
	afx_msg void OnBnClickedBtnScanRemoveip();

	// 리스트 컨트롤 변수 및 함수
	CListCtrl m_ListCtrlScanResult;
	afx_msg void OnListIPStatusCustomdraw(NMHDR* pNMHDR, LRESULT* pResult);
	void ListCtrlInit();
	void ListCtrlDeleteAll();
	void ListCtrlInsertData(IPStatusInfo *item);
	int *GetCheckedItem();
	bool IsListUpdateThreadDye() { return m_IsListUpdateThreadDye; }
	void ListCtrlUpdate(){ m_EventListUpdate.SetEvent(); }

	// 아이피 입력 컨트롤 변수 및 함수
	CIPAddressCtrl m_IPAddrCtrlBeginIP;
	CIPAddressCtrl m_IPAddrCtrlEndIP;
	void IPAddrCtrlInit();

	// 스테이터스바 컨트롤 변수 및 함수
	CStatusBarCtrl m_StatusBarCtrl;
	void StatusBarCtrlInit();
	void StatusBarCtrlUpdate(int index, wchar_t* string);

	// 체크박스 컨트롤 변수 및 함수
	CButton m_CheckBoxCtrlIsHideDeadIP;		// HideDeadIP
	
	// 스캐너 클래스
	CNetworkIPScan m_NetworkIPScan;

	// NICInfoDlg
	CNICInfoDlg m_NICInfoDlg;
	CComboBox m_ComboCtrlNICInfo;
	// NIC 선택용 콤보 박스
	void ComboBoxInit();

	afx_msg void OnClose();
};
