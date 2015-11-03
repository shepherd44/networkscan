
// IPScannerDlg.h : 헤더 파일
//

#pragma once
#include "afxcmn.h"
 
#include "NetworkIPScan.h"

// CIPScannerDlg 대화 상자
class CIPScannerDlg : public CDialogEx
{
// 생성입니다.
public:
	CIPScannerDlg(CWnd* pParent = NULL);	// 표준 생성자입니다.

// 대화 상자 데이터입니다.
	enum { IDD = IDD_IPSCANNER_DIALOG };

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
	// 버튼 클릭 이벤트 처리
	afx_msg void OnBnClickedBtnScan();
	// 리스트 컨트롤 배경색 처리
	afx_msg void OnListIPStatusCustomdraw(NMHDR* pNMHDR, LRESULT* pResult);
	DECLARE_MESSAGE_MAP()

// 멤버 변수
protected:
	// IP 상태 스캔 클래스
	CNetworkIPScan m_networkIPScanner;

private:
	// 초기화 함수
	void InitializeAll();		// 전체 초기화
	void ListCtrlInit();		// 리스트 컨트롤 초기화
	void IPAddressCtrlInit();	// IP주소 컨트롤 초기화
	
public:
	// 리스트 컨트롤 변수
	CListCtrl m_ListIPStatus;

	// IPAddress 입력 컨트롤
	CIPAddressCtrl m_IPAddressBeginIP;
	CIPAddressCtrl m_IPAddressEndIP;
	
public:
	// 리스트 컨트롤 관련 함수
	void ListCtrlInsertData(IPStatusInfo *ipstat);
	void ListCtrlDeleteAll();
	void Display();
};

