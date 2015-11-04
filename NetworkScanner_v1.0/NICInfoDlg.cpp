// NICInfoDlg.cpp : 구현 파일입니다.
//

#include "stdafx.h"
#include "NetworkScanner.h"
#include "NetworkScannerDlg.h"
#include "NICInfoDlg.h"
#include "afxdialogex.h"


// CNICInfoDlg 대화 상자입니다.

IMPLEMENT_DYNAMIC(CNICInfoDlg, CDialogEx)

CNICInfoDlg::CNICInfoDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CNICInfoDlg::IDD, pParent)
{ }

CNICInfoDlg::~CNICInfoDlg()
{ }

void CNICInfoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_NICInfoList, m_ListCtrlNICInfoList);
}


BEGIN_MESSAGE_MAP(CNICInfoDlg, CDialogEx)
	ON_BN_CLICKED(ID_BTN_SELECT, &CNICInfoDlg::OnBnClickedBtnSelect)
	ON_BN_CLICKED(IDCANCEL, &CNICInfoDlg::OnBnClickedCancel)
END_MESSAGE_MAP()


// CNICInfoDlg 메시지 처리기입니다.

//------------------------------------------------------------------------
// 자동 생성 끝
//------------------------------------------------------------------------

//------------------------------------------------------------------------
// 초기화
//------------------------------------------------------------------------
BOOL CNICInfoDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	InitializeAll();
	return true;
}

void CNICInfoDlg::InitializeAll()
{
	ListCtrlNICInfoInit();
}

void CNICInfoDlg::ListCtrlNICInfoInit()
{
	// static wchar_t *ListCtrlColumnString[] 선언
	LISTCTRLNICINFO_COULMNSTRING;	

	m_ListCtrlNICInfoList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	// 열 설정
	int i = 0, size = sizeof(ListCtrlColumnString) / sizeof(wchar_t*);
	m_ListCtrlNICInfoList.InsertColumn(i, ListCtrlColumnString[i], LVCFMT_LEFT, LIST_COLUMN_NUMBER_LENGTH, -1);
	i++;
	for (; i < size; i++)
		m_ListCtrlNICInfoList.InsertColumn(i, ListCtrlColumnString[i], LVCFMT_LEFT, LIST_COLUMN_LENGTH, -1);

	// Main Dlg 가져오기
	CNetworkScannerDlg *temp = (CNetworkScannerDlg*)AfxGetApp()->GetMainWnd();

	// nic list 가져오기: Network Scanner의 SendSocket을 이용
	CNICInfoList *niclist = temp->m_NetworkIPScan.GetNicInfoList();

	NICInfo *nicitem;
	CString str;
	size = niclist->GetSize();
	
	// NIC 정보 삽입
	// 리스트 컨트롤 초기화
	m_ListCtrlNICInfoList.DeleteAllItems();	
	// NIC 정보 출력
	for (i = 0; i < size; i++)
	{
		nicitem = niclist->At(i);

		// 1열
		str.Format(_T("%d"), i + 1);
		m_ListCtrlNICInfoList.InsertItem(i, str);
		m_ListCtrlNICInfoList.SetItem(i, 1, LVIF_TEXT, CString(nicitem->Description), 0, 0, 0, NULL);

		// 2열
		str.Format(_T("%d.%d.%d.%d"),
			(nicitem->NICIPAddress) & 0xff,
			(nicitem->NICIPAddress >> 8) & 0xff,
			(nicitem->NICIPAddress >> 16) & 0xff,
			(nicitem->NICIPAddress >> 24) & 0xff);
		m_ListCtrlNICInfoList.SetItem(i, 2, LVIF_TEXT, str, 0, 0, 0, NULL);

		// 3열
		str.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"), 
			nicitem->NICMACAddress[0],
			nicitem->NICMACAddress[1], 
			nicitem->NICMACAddress[2], 
			nicitem->NICMACAddress[3], 
			nicitem->NICMACAddress[4], 
			nicitem->NICMACAddress[5] );
		m_ListCtrlNICInfoList.SetItem(i, 3, LVIF_TEXT, str, 0, 0, 0, NULL);

		// 4열
		str.Format(_T("%d.%d.%d.%d"),
			(nicitem->Netmask) & 0xff,
			(nicitem->Netmask >> 8) & 0xff,
			(nicitem->Netmask >> 16) & 0xff,
			(nicitem->Netmask >> 24) & 0xff);
		m_ListCtrlNICInfoList.SetItem(i, 4, LVIF_TEXT, str, 0, 0, 0, NULL);
	}
}

//------------------------------------------------------------------------
// 자동 생성 끝
//------------------------------------------------------------------------

void CNICInfoDlg::OnBnClickedBtnSelect()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	int selected = -1;

	POSITION pos = m_ListCtrlNICInfoList.GetFirstSelectedItemPosition();
	while (pos)
	{
		selected = m_ListCtrlNICInfoList.GetNextSelectedItem(pos);
		break;
	}

	// 선택 안한 경우 0번 선택
	if (selected == -1)
	{
		AfxMessageBox(_T("하나를 선택해 주세요."));
		return;
	}
	// 선택된 NIC 반환
	this->EndModalLoop(selected);
}

void CNICInfoDlg::OnBnClickedCancel()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	// CDialogEx::OnCancel();
	this->EndModalLoop(-1);
}
