#pragma once
#include "afxcmn.h"

// 리스트 컨트롤 컬럼 길이
#if LIST_COLUMN_LENGTH
#undef LIST_COLUMN_LENGTH
#undef LIST_COLUMN_NUMBER_LENGTH
#define LIST_COLUMN_LENGTH	100
#define	LIST_COLUMN_NUMBER_LENGTH	40
#else if
#define LIST_COLUMN_LENGTH	100
#define	LIST_COLUMN_NUMBER_LENGTH	40
#endif

// 리스트 컨트롤 컬럼 스트링 선언 매크로
#define LISTCTRLNICINFO_COULMNSTRING	static wchar_t *ListCtrlColumnString[] = {	\
																_T("No"),			\
																_T("NIC Name"),		\
																_T("IP Address"),	\
																_T("MAC Address"),	\
																_T("Netmask")		\
																}

// CNICInfoDlg 대화 상자입니다.

class CNICInfoDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CNICInfoDlg)

public:
	CNICInfoDlg(CWnd* pParent = NULL);   // 표준 생성자입니다.
	virtual ~CNICInfoDlg();

// 대화 상자 데이터입니다.
	enum { IDD = IDD_DIALOG_NICINFO };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

	DECLARE_MESSAGE_MAP()

protected:
public:
	// 컨트롤 함수 및 변수
	afx_msg void OnBnClickedBtnSelect();
	afx_msg void OnBnClickedCancel();

	virtual BOOL OnInitDialog();

	// 리스트 컨트롤
	CListCtrl m_ListCtrlNICInfoList;
	void ListCtrlNICInfoInit();
	
	void InitializeAll();
	
};
