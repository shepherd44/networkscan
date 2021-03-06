
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

// IPSTATUSINFO 셀 배경색 선언 매크로
// IPSTATUS 열거형 순서대로
#define IPSTATUS_CELLCOLOR__	static COLORREF ipstatcolor[] =	{				\
														RGB(255, 255, 255),	\
														RGB(250, 250, 210),	\
														RGB(0, 200, 0),		\
														RGB(200, 0, 0),		\
														RGB(0, 200, 200),		\
													}
#define IPSTATUS_CELLCOLOR(index)	ipstatcolor[index]

// 스테이터스바 컨트롤 관련 매크로
// SCANNING_STATE 순서대로 나열
#define STATUSBARCTRL_STRING__	static wchar_t *statusbarstring[] = {		\
	_T("Program start. Scannig Available"),									\
	_T("Scan start. Sending Packet."),										\
	_T("Sending ARP Packet and Capture"),									\
	_T("Sending ICMP Packet and Capture."),									\
	_T("Packet send complete and Capture. "),								\
	_T("Stop scannig"),														\
	_T("Stop send packet, and Packet capture"),								\
	_T("Stop captue packet, and Packet Send"),								\
	_T("Program End. Wait...")												\
};
#define STATUSBARCTRL_STRING(index)		statusbarstring[index]
// 버튼 클릭 상태 처리용 enum
enum SCANNIG_STATE
{
	BEGIN = 0,			// 처음 시작시
	SCANNIG,			// 스캔 시작 시
	SCANNING_ARPSEND,	// ARP 패킷 전송 
	SCANNING_PINGSEND,	// ICMP 패킷 전송
	SCANNING_SENDINGCOMPLETE,	// 
	STOP_ALL,			// 패킷 전송, 캡처 모두 중지
	STOP_SEND,			// IP 상태 확인용 패킷 전송 중지
	STOP_RECV,			// 패킷 캡처 및 분석 중지
	PROGRAM_END,		// 프로그램 종료중
	
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

	CIPStatusList m_ViewListBuffer;
	// 리스트 컨트롤 업데이트 쓰레드
	CWinThread *m_ListUpdateThread;
	// 리스트 컨트롤 중지용 변수
	bool m_IsListUpdateThreadDye;

	// 리스트 컨트롤 업데이트 쓰레드 시작
	void StartListUpdateThread();
	// 리스트 컨트롤 업데이트 쓰레드 중지
	void EndListUpdateThread();
	// 리스트 컨트롤 업데이드 쓰레드 함수
	static UINT AFX_CDECL ListUpdateThreadFunc(LPVOID lpParam);

	// 프로그램 상태
	SCANNIG_STATE m_ProgramState;

// 컨트롤 변수 및 함수
public:
	// 종료
	afx_msg void OnClose();

	// 버튼 클릭 이벤트 처리
	afx_msg void OnBnClickedBtnScan();			// 스캔 시작 버튼
	afx_msg void OnBnClickedBtnStopAll();		// 스캔 중지
	afx_msg void OnBnClickedBtnStopSend();		// 패킷 전송 중지
//	afx_msg void OnBnClickedBtnStopRecv();		// 패킷 캡처 중지
	afx_msg void OnBnClickedBtnNicdetail();		// NIC 정보 자세히 보기
	afx_msg void OnBnClickedBtnScanAddip();		// IP 추가
	afx_msg void OnBnClickedBtnScanRemoveip();	// IP 제거

	// 리스트 컨트롤 변수 및 함수
	CListCtrl m_ListCtrlScanResult;
	vector<bool> m_VectorColumnDirection;
	// 리스트 컨트롤 유저 지정 통지 함수
	afx_msg void OnListIPStatusCustomdraw(NMHDR* pNMHDR, LRESULT* pResult);
	// 오너드로우
	afx_msg void OnLvnGetdispinfoListScanresult(NMHDR *pNMHDR, LRESULT *pResult);
	// 리스트 컨트롤 초기화 함수
	void ListCtrlInit();
	// 체크박스로 체크된 항목 가져오기(미구현)
	int *GetCheckedItem();
	// 리스트 컨트롤 업데이트 쓰레드 상태 확인
	bool IsListUpdateThreadDye() { return m_IsListUpdateThreadDye; }
	// 리스트 컨트롤 헤더 클릭 처리함수
	void OnHdnItemClick(NMHDR*, LRESULT*);

	// 아이피 입력 컨트롤 변수 및 함수
	CIPAddressCtrl m_IPAddrCtrlBeginIP;
	CIPAddressCtrl m_IPAddrCtrlEndIP;
	// 아이피 입력 컨트롤 초기화
	void IPAddrCtrlInit();

	// 스테이터스바 컨트롤 변수 및 함수
	CStatusBarCtrl m_StatusBarCtrl;
	// 스테이터스바 컨트롤 초기화
	void StatusBarCtrlInit();
	// 스테이터스바 컨트롤 업데이트
	void StatusBarCtrlUpdate();
	void StatusBarCtrlUpdate(wchar_t* string);

	// 체크박스 컨트롤 변수 및 함수
	CButton m_CheckBoxCtrlIsHideDeadIP;
	afx_msg void OnBnClickedCheckHidedeadip();

	// 스캐너 클래스
	CNetworkIPScan m_NetworkIPScan;

	// NICInfoDlg
	CNICInfoDlg m_NICInfoDlg;
	CComboBox m_ComboCtrlNICInfo;
	// NIC 선택용 콤보 박스
	void ComboBoxInit();

	// 프로그램 상태 확인
	void SetProgramState(SCANNIG_STATE state) { m_ProgramState = state; }
	int GetProgeamState() { return m_ProgramState; }
	
	void ViewUpdate();
	void UpdateListCtrl(int index);
	afx_msg void OnBnClickedBtnScanIPAddFromExcel();
	afx_msg void OnBnClickedBtnScanExportip();
};
