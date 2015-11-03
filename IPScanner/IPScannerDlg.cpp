
// IPScannerDlg.cpp : 구현 파일
//

#include "stdafx.h"
#include "IPScanner.h"
#include "IPScannerDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 응용 프로그램 정보에 사용되는 CAboutDlg 대화 상자입니다.

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 대화 상자 데이터입니다.
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

// 구현입니다.
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CIPScannerDlg 대화 상자



CIPScannerDlg::CIPScannerDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CIPScannerDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

// 컨트롤 - 멤버 변수 연결
void CIPScannerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_IPADDRESS_BEGINIP, m_IPAddressBeginIP);
	DDX_Control(pDX, IDC_IPADDRESS_ENDIP, m_IPAddressEndIP);
	DDX_Control(pDX, IDC_LIST_IPStatus, m_ListIPStatus);
}

// 메시지 맵
BEGIN_MESSAGE_MAP(CIPScannerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(ID_BTN_SCAN, &CIPScannerDlg::OnBnClickedBtnScan)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST_IPStatus, CIPScannerDlg::OnListIPStatusCustomdraw)
END_MESSAGE_MAP()


// CIPScannerDlg 메시지 처리기

BOOL CIPScannerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 시스템 메뉴에 "정보..." 메뉴 항목을 추가합니다.

	// IDM_ABOUTBOX는 시스템 명령 범위에 있어야 합니다.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 이 대화 상자의 아이콘을 설정합니다.  응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.
	InitializeAll();

	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

void CIPScannerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다.  문서/뷰 모델을 사용하는 MFC 응용 프로그램의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CIPScannerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트입니다.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CIPScannerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

// 자동 생성 함수 끝
//--------------------------------------------------------------------------------
// 리스트 컨트롤 통지 함수
afx_msg void CIPScannerDlg::OnListIPStatusCustomdraw(NMHDR* pNMHDR, LRESULT* pResult)
{
	// IPSTATUSINFO 
	static COLORREF ipstatcolor[] =
	{
		RGB(255, 255, 255),		// Dead IP
		RGB(250, 250, 210),		// Using
		RGB(0, 200, 0),			// GateWay
		RGB(200, 0, 0),			// IP Duplication
		RGB(0, 0, 255),			// Other Network
	};

	NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);
	*pResult = CDRF_DODEFAULT;
	if (pLVCD->nmcd.dwDrawStage == CDDS_PREPAINT)
		*pResult = CDRF_NOTIFYITEMDRAW;
	else if (pLVCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
	{
		int nItem = static_cast<int>(pLVCD->nmcd.dwItemSpec);
		pLVCD->clrTextBk = ipstatcolor[m_networkIPScanner[nItem].m_IPStatus];
		*pResult = CDRF_DODEFAULT;
	}
}

// Scan 버튼 클릭 이벤트 처리기
void CIPScannerDlg::OnBnClickedBtnScan()
{
	// 입력된 IP 주소 처리
	u_long beginip, endip;
	u_long size = 0;
	m_IPAddressBeginIP.GetAddress(beginip);
	m_IPAddressEndIP.GetAddress(endip);

	// 입력 범위 체크
	if (beginip > endip)
	{
		AfxMessageBox(_T("IP 범위를 반대로 입력하였습니다."));
		return;
	}

	// 스캔 시작
	m_networkIPScanner.Scan(beginip, endip);
	// 출력
	Display();
}

// 초기화 함수
void CIPScannerDlg::InitializeAll()
{
	HANDLE m_hCaptureThread = NULL;
	ListCtrlInit();
	IPAddressCtrlInit();
}

// 리스트 컨트롤 초기화
void CIPScannerDlg::ListCtrlInit()
{
	ListCtrlDeleteAll();
	m_ListIPStatus.SetExtendedStyle(LVS_EX_GRIDLINES);

	// 열 설정
	m_ListIPStatus.InsertColumn(0, _T("IP Address"), LVCFMT_LEFT, 140, -1);
	m_ListIPStatus.InsertColumn(1, _T("IP Status"), LVCFMT_LEFT, 140, -1);
	m_ListIPStatus.InsertColumn(2, _T("MAC Address"), LVCFMT_LEFT, 140, -1);
}

// 리스트 컨트롤 데이터 삽입
void CIPScannerDlg::ListCtrlInsertData(IPStatusInfo *ipstat)
{
	// 출력용 스트링 변수 배열
	static wchar_t *ipstatstr[] =
	{
		TEXT("NOT USING"),
		TEXT("USING"),
		TEXT("GATEWAY"),
		TEXT("UNKNOWN"),
		TEXT("IP DUPLICATION"),
		TEXT("OTHER NETWORK")
	};

	u_char *ucptemp = reinterpret_cast<u_char*>(&ipstat->m_IPAddress);
	CString str;
	
	// 1열 IP Address 삽입
	str.Format(TEXT("%d.%d.%d.%d"), ucptemp[0], ucptemp[1], ucptemp[2], ucptemp[3]);
	int index = m_ListIPStatus.GetItemCount();
	m_ListIPStatus.InsertItem(index, str);

	// 2열 IP Status 삽입
	str.Format(TEXT("%s"), ipstatstr[ipstat->m_IPStatus]);
	m_ListIPStatus.SetItem(index, 1, LVIF_TEXT, str, 0, 0, 0, NULL);
	
	// 3열 MAC Address 삽입
	ucptemp = reinterpret_cast<u_char*>(&ipstat->m_MACAddress);
	str.Format(TEXT("%02X:%02X:%02X:%02X:%02X:%02X"), ucptemp[0], ucptemp[1], ucptemp[2],
												ucptemp[3], ucptemp[4], ucptemp[5]);
	m_ListIPStatus.SetItem(index, 2, LVIF_TEXT, str, 0, 0, 0, NULL);
}

// 리스트 컨트롤 내용 비우기
void CIPScannerDlg::ListCtrlDeleteAll()
{
	m_ListIPStatus.DeleteAllItems();
}

// IPAddr 컨트롤 초기화
void CIPScannerDlg::IPAddressCtrlInit()
{
	u_long nicip, nicnetmask, nichostmask;
	u_long beginip, endip;

	memcpy(&nicip, m_networkIPScanner.GetNICIPAddress(), IPV4ADDRESSLENGTH);
	memcpy(&nicnetmask, m_networkIPScanner.GetNICNetmask(), IPV4ADDRESSLENGTH);
	nichostmask = nicnetmask ^ 0xffffffff;
	
	// 네트워크 대역 검사
	beginip = nicip & nicnetmask;
	endip = beginip + nichostmask;

	u_char *casttemp1 = reinterpret_cast<u_char*>(&beginip);
	u_char *casttemp2 = reinterpret_cast<u_char*>(&endip);
	// Begin IP input 범위 제한
	m_IPAddressBeginIP.SetFieldRange(0, static_cast<char>(casttemp1[0]), static_cast<char>(casttemp2[0]));
	m_IPAddressBeginIP.SetFieldRange(1, static_cast<char>(casttemp1[1]), static_cast<char>(casttemp2[1]));
	m_IPAddressBeginIP.SetFieldRange(2, static_cast<char>(casttemp1[2]), static_cast<char>(casttemp2[2]));
	m_IPAddressBeginIP.SetFieldRange(3, static_cast<char>(casttemp1[3]), static_cast<char>(casttemp2[3]));

	// End IP input 범위 제한
	m_IPAddressEndIP.SetFieldRange(0, static_cast<char>(casttemp1[0]), static_cast<char>(casttemp2[0]));
	m_IPAddressEndIP.SetFieldRange(1, static_cast<char>(casttemp1[1]), static_cast<char>(casttemp2[1]));
	m_IPAddressEndIP.SetFieldRange(2, static_cast<char>(casttemp1[2]), static_cast<char>(casttemp2[2]));
	m_IPAddressEndIP.SetFieldRange(3, static_cast<char>(casttemp1[3]), static_cast<char>(casttemp2[3]));

	// 첫 주소 셋팅
	m_IPAddressBeginIP.SetAddress(static_cast<char>(casttemp1[0]),
								  static_cast<char>(casttemp1[1]),
								  static_cast<char>(casttemp1[2]),
								  static_cast<char>(casttemp1[3]) + 1);
	m_IPAddressEndIP.SetAddress(static_cast<char>(casttemp2[0]),
								static_cast<char>(casttemp2[1]),
								static_cast<char>(casttemp2[2]),
								static_cast<char>(casttemp2[3]) - 1);
}

// 결과 리스트 컨트롤로 반영
void CIPScannerDlg::Display()
{
	// 리스트 컨트롤 비우기
	ListCtrlDeleteAll();
	// 결과 리스트 컨트롤에 삽입
	int vecend = m_networkIPScanner.GetIPStatusVector().GetSize();
	for (int i = 0; i < vecend; i++)
		ListCtrlInsertData(&m_networkIPScanner[i]);
}