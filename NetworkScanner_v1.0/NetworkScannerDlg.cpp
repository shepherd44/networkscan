
// NetworkScanner_v1.0Dlg.cpp : 구현 파일
//

#include "stdafx.h"
#include "NetworkScanner.h"
#include "NetworkScannerDlg.h"
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


// CNetworkScannerDlg 대화 상자


CNetworkScannerDlg::CNetworkScannerDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CNetworkScannerDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CNetworkScannerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_SCANRESULT, m_ListCtrlScanResult);
	DDX_Control(pDX, IDC_IPADDRESS_BEGINIP, m_IPAddrCtrlBeginIP);
	DDX_Control(pDX, IDC_IPADDRESS_ENDIP, m_IPAddrCtrlEndIP);
	DDX_Control(pDX, IDC_CHECK_HIDEDEADIP, m_CheckBoxCtrlIsHideDeadIP);
	DDX_Control(pDX, IDC_COMBO_NICINFO, m_ComboCtrlNICInfo);
}

BEGIN_MESSAGE_MAP(CNetworkScannerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(ID_BTN_SCAN, &CNetworkScannerDlg::OnBnClickedBtnScan)
	ON_BN_CLICKED(ID_BTN_STOP_SEND, &CNetworkScannerDlg::OnBnClickedBtnStopSend)
	ON_BN_CLICKED(ID_BTN_STOP_RECV, &CNetworkScannerDlg::OnBnClickedBtnStopRecv)
	ON_BN_CLICKED(ID_BTN_STOP_ALL, &CNetworkScannerDlg::OnBnClickedBtnStopAll)
	ON_BN_CLICKED(ID_BTN_NICDETAIL, &CNetworkScannerDlg::OnBnClickedBtnNicdetail)
	ON_BN_CLICKED(ID_BTN_SCAN_ADDIP, &CNetworkScannerDlg::OnBnClickedBtnScanAddip)
	ON_BN_CLICKED(ID_BTN_SCAN_REMOVEIP, &CNetworkScannerDlg::OnBnClickedBtnScanRemoveip)
END_MESSAGE_MAP()


// CNetworkScannerDlg 메시지 처리기

BOOL CNetworkScannerDlg::OnInitDialog()
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

void CNetworkScannerDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CNetworkScannerDlg::OnPaint()
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
HCURSOR CNetworkScannerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//--------------------------------------------------------------
// 자동 생성 함수 끝
//--------------------------------------------------------------

//--------------------------------------------------------------
// 버튼 클릭 처리 이벤트 함수
//--------------------------------------------------------------

void CNetworkScannerDlg::OnBnClickedBtnScan()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	
	// 버튼 클릭 제한
	CButton *btn = (CButton *)GetDlgItem(ID_BTN_NICDETAIL);
	btn->EnableWindow(FALSE);
	// 콤보박스 클릭 제한
	m_ComboCtrlNICInfo.EnableWindow(FALSE);
	
	// 
	int nicindex = m_ComboCtrlNICInfo.GetCurSel();

	// 스캔 시작
	m_NetworkIPScan.Scan(nicindex);

}

void CNetworkScannerDlg::OnBnClickedBtnStopAll()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.

	// 패킷 전송 스레드 중지
	m_NetworkIPScan.EndSend();
	// 패킷 캡처 스레드 중지
	m_NetworkIPScan.EndCapture();
	// 컨트롤 활성화
	// 버튼 클릭 제한
	CButton *btn = (CButton *)GetDlgItem(ID_BTN_NICDETAIL);
	btn->EnableWindow(TRUE);
	// 콤보박스 클릭 제한
	m_ComboCtrlNICInfo.EnableWindow(TRUE);
}

void CNetworkScannerDlg::OnBnClickedBtnStopSend()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
}

void CNetworkScannerDlg::OnBnClickedBtnStopRecv()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
}

// NIC Information 자세히 보기
void CNetworkScannerDlg::OnBnClickedBtnNicdetail()
{
	// 모달로 실행
	int selected = m_NICInfoDlg.DoModal();
	if(selected != -1)
		m_ComboCtrlNICInfo.SetCurSel(selected);	
}

void CNetworkScannerDlg::OnBnClickedBtnScanAddip()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	u_long hbeginip, hendip;
	uint8_t mac[MACADDRESS_LENGTH];
	memset(mac, 0, MACADDRESS_LENGTH);
	m_IPAddrCtrlBeginIP.GetAddress(hbeginip);
	m_IPAddrCtrlEndIP.GetAddress(hendip);

	if (hbeginip > hendip)
	{
		AfxMessageBox(_T("IP 범위를 반대로 입력하였습니다."));
		return;
	}
	
	int size = 0;
	int i = 0;
	CIPStatusList *iplist = m_NetworkIPScan.GetIpStatusList();
	
	for (; hbeginip <= hendip; hbeginip++)
		iplist->AddItem(htonl(hbeginip), mac, IPSTATUS::NOTUSING, false);

	m_EventListUpdate.SetEvent();
}

void CNetworkScannerDlg::OnBnClickedBtnScanRemoveip()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	int count = m_ListCtrlScanResult.GetItemCount();
	for (int i = 0; i < count; i++)
	{
		BOOL a = m_ListCtrlScanResult.GetCheck(i);
		if (a == TRUE)
		{
			CString temp = m_ListCtrlScanResult.GetItemText(i, 0);
			temp.Format(_T("%s seq가 선택됨"), temp);
			AfxMessageBox(temp);
		}
	}
}


//--------------------------------------------------------------
// 초기화 함수들
//--------------------------------------------------------------
void CNetworkScannerDlg::InitializeAll()
{
	ListCtrlInit();
	IPAddrCtrlInit();
	StatusBarCtrlInit();
	ComboBoxInit();
	m_ListUpdateThread = NULL;
	StartListUpdateThread();
	// 리스트 컨트롤 ui 스레드 시작 추가
}

// NIC 선택 콤보 박스
void CNetworkScannerDlg::ComboBoxInit()
{
	CNICInfoList *nicinfolist = m_NetworkIPScan.GetNicInfoList();
	NICInfo *nicinfo;
	int size = nicinfolist->GetSize();
	char des[28];
	memset(des, '\0', 28);
	for (int i = 0; i < size; i++)
	{
		nicinfo = nicinfolist->At(i);
		if (strlen(nicinfo->Description) > 25)
		{
			memcpy(des, nicinfo->Description, 24);
			memcpy(des + 24, "...", 4);
		}
		m_ComboCtrlNICInfo.AddString(CString(des));
	}
	
	m_ComboCtrlNICInfo.SetCurSel(0);
}

// 리스트 컨트롤 초기화
void CNetworkScannerDlg::ListCtrlInit()
{
	LISTCTRL_COULMNSTRING;	// static wchar_t *ListCtrlColumnString[] 선언
	ListCtrlDeleteAll();
	
	// 체크박스 체크방법
	// SetCheck(i, false)
	m_ListCtrlScanResult.SetExtendedStyle(LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	// 열 설정
	int i = 0, size = sizeof(ListCtrlColumnString) / sizeof(wchar_t*);
	m_ListCtrlScanResult.InsertColumn(i, ListCtrlColumnString[i++], LVCFMT_LEFT, LIST_COLUMN_NUMBER_LENGTH, -1);
	m_ListCtrlScanResult.InsertColumn(i, ListCtrlColumnString[i++], LVCFMT_LEFT, LIST_COLUMN_NUMBER_LENGTH, -1);
	for (; i < size; i++)
		m_ListCtrlScanResult.InsertColumn(i, ListCtrlColumnString[i], LVCFMT_LEFT, LIST_COLUMN_LENGTH, -1);
}

void CNetworkScannerDlg::ListCtrlDeleteAll()
{
	m_ListCtrlScanResult.DeleteAllItems();
}

// IP 입력 컨트롤 초기화
void CNetworkScannerDlg::IPAddrCtrlInit()
{
	u_long nicip, nicnetmask, nichostmask;
	u_long beginip, endip;

	CNICInfoList *list = m_NetworkIPScan.GetNicInfoList();
	NICInfo *nicinfo = list->At(m_ComboCtrlNICInfo.GetCurSel());
	nicip = nicinfo->NICIPAddress;
	nicnetmask = nicinfo->Netmask;
	nichostmask = nicnetmask ^ 0xffffffff;

	// 네트워크 대역 검사
	beginip = nicip & nicnetmask;
	endip = beginip + nichostmask;

	u_char *casttemp1 = reinterpret_cast<u_char*>(&beginip);
	u_char *casttemp2 = reinterpret_cast<u_char*>(&endip);
	// Begin IP input 범위 제한
	m_IPAddrCtrlBeginIP.SetFieldRange(0, static_cast<char>(casttemp1[0]), static_cast<char>(casttemp2[0]));
	m_IPAddrCtrlBeginIP.SetFieldRange(1, static_cast<char>(casttemp1[1]), static_cast<char>(casttemp2[1]));
	//m_IPAddrCtrlBeginIP.SetFieldRange(2, static_cast<char>(casttemp1[2]), static_cast<char>(casttemp2[2]));
	//m_IPAddrCtrlBeginIP.SetFieldRange(3, static_cast<char>(casttemp1[3]), static_cast<char>(casttemp2[3]));

	// End IP input 범위 제한
	m_IPAddrCtrlEndIP.SetFieldRange(0, static_cast<char>(casttemp1[0]), static_cast<char>(casttemp2[0]));
	m_IPAddrCtrlEndIP.SetFieldRange(1, static_cast<char>(casttemp1[1]), static_cast<char>(casttemp2[1]));
	//m_IPAddrCtrlEndIP.SetFieldRange(2, static_cast<char>(casttemp1[2]), static_cast<char>(casttemp2[2]));
	//m_IPAddrCtrlEndIP.SetFieldRange(3, static_cast<char>(casttemp1[3]), static_cast<char>(casttemp2[3]));

	// 첫 주소 셋팅
	m_IPAddrCtrlBeginIP.SetAddress(static_cast<char>(casttemp1[0]),
		static_cast<char>(casttemp1[1]),
		static_cast<char>(casttemp1[2]),
		static_cast<char>(casttemp1[3]) + 1);
	m_IPAddrCtrlEndIP.SetAddress(static_cast<char>(casttemp2[0]),
		static_cast<char>(casttemp2[1]),
		static_cast<char>(casttemp2[2]),
		static_cast<char>(casttemp2[3]) - 1);

}

void CNetworkScannerDlg::ListCtrlInsertData(IPStatusInfo *item)
{
	// 출력용 스트링 변수 배열
	static wchar_t *ipstatstr[] =
	{
		TEXT("NOT USING"),
		TEXT("USING"),
		TEXT("GATEWAY"),
		TEXT("IP DUPLICATION"),
	};
	
	CString str;
	int index = m_ListCtrlScanResult.GetItemCount();
	// 1열 체크박스
	m_ListCtrlScanResult.InsertItem(index, str);

	// 2열 번호
	str.Format(_T("%d"), index + 1);
	m_ListCtrlScanResult.SetItem(index, 1, LVIF_TEXT, str, 0, 0, 0, NULL);

	// 3열 IP Address 삽입
	str.Format(_T("%d.%d.%d.%d"), (item->IPAddress) & 0xff, (item->IPAddress >> 8) & 0xff, (item->IPAddress >> 16) & 0xff, (item->IPAddress >> 24) & 0xff);
	m_ListCtrlScanResult.SetItem(index, 2, LVIF_TEXT, str, 0, 0, 0, NULL);

	// 4열 MAC  삽입
	str.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"), item->MACAddress[0], item->MACAddress[1], item->MACAddress[2], 
		item->MACAddress[3], item->MACAddress[4], item->MACAddress[5]);
	m_ListCtrlScanResult.SetItem(index, 3, LVIF_TEXT, str, 0, 0, 0, NULL);

	// 5열 IP Status 삽입
	str.Format(ipstatstr[item->IPStatus]);
	m_ListCtrlScanResult.SetItem(index, 4, LVIF_TEXT, str, 0, 0, 0, NULL);

	// 6열 Ping
	str.Format(_T("%s"), item->PingReply ? "O" :"X");
	m_ListCtrlScanResult.SetItem(index, 5, LVIF_TEXT, str, 0, 0, 0, NULL);
}

// 리스트 컨트롤 통지 함수
afx_msg void CNetworkScannerDlg::OnListIPStatusCustomdraw(NMHDR* pNMHDR, LRESULT* pResult)
{
	IPSTATUS_CELLCOLOR;		// static COLORREF ipstatcolor[] 선언

	NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);
	*pResult = CDRF_DODEFAULT;
	if (pLVCD->nmcd.dwDrawStage == CDDS_PREPAINT)
		*pResult = CDRF_NOTIFYITEMDRAW;
	else if (pLVCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
	{
		int nItem = static_cast<int>(pLVCD->nmcd.dwItemSpec);
		// 색 지정
		//pLVCD->clrTextBk = ipstatcolor[m_networkIPScanner[nItem].m_IPStatus];
		*pResult = CDRF_DODEFAULT;
	}
}

void CNetworkScannerDlg::StatusBarCtrlInit()
{
	m_StatusBarCtrl.Create(WS_CHILD | WS_VISIBLE | SBT_OWNERDRAW, CRect(0, 0, 0, 0), this, 0);
	CRect rect;
	GetClientRect(&rect);
	int strPartDim[2] = { rect.right / 2, -1 };
	m_StatusBarCtrl.SetParts(1, strPartDim);
	m_StatusBarCtrl.SetText(_T("Program Start. Scannig Available"), 0, 0);
	m_StatusBarCtrl.SetIcon(3, SetIcon(AfxGetApp()->LoadIcon(IDR_MAINFRAME), FALSE));
}

void CNetworkScannerDlg::StartListUpdateThread()
{
	if (m_ListUpdateThread == NULL)
	{
		m_IsListUpdateThreadDye = false;
		LPVOID param = &m_IsListUpdateThreadDye;
		m_ListUpdateThread = AfxBeginThread(ListUpdateThreadFunc, param, 0, 0, 0);
	}
	else
	{
		throw std::exception("list update thread 생성 실패");
	}
}
void CNetworkScannerDlg::EndListUpdateThread()
{
	m_IsListUpdateThreadDye = true;
	WaitForSingleObject(m_ListUpdateThread->m_hThread, INFINITE);
	
	m_ListUpdateThread = NULL;
}


UINT AFX_CDECL CNetworkScannerDlg::ListUpdateThreadFunc(LPVOID lpParam)
{
	bool *isdye = (bool *)lpParam;
	CNetworkScannerDlg *maindlg = (CNetworkScannerDlg*)AfxGetApp()->GetMainWnd();
	while (1)
	{
		maindlg->m_EventListUpdate.Lock();
		maindlg->ListCtrlDeleteAll();
		CIPStatusList *iplist = (maindlg->m_NetworkIPScan.GetIpStatusList());
		int size = iplist->GetSize();

		for (int i = 0; i < size; i++)
		{
			maindlg->ListCtrlInsertData(iplist->At(i));
		}

		// 쓰레드 종료 확인
		if (isdye)
			break;
	}
	return 0;
}