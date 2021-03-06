
// NetworkScanner_v1.0Dlg.cpp : 구현 파일
//

#include "stdafx.h"
//#include "NetworkScanner.h"
//#include "NetworkScannerDlg.h"
#include "afxdialogex.h"
#include "NetworkScannerDlg.h"

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
	ON_BN_CLICKED(ID_BTN_STOP_ALL, &CNetworkScannerDlg::OnBnClickedBtnStopAll)
	ON_BN_CLICKED(ID_BTN_NICDETAIL, &CNetworkScannerDlg::OnBnClickedBtnNicdetail)
	ON_BN_CLICKED(ID_BTN_SCAN_ADDIP, &CNetworkScannerDlg::OnBnClickedBtnScanAddip)
	ON_BN_CLICKED(ID_BTN_SCAN_REMOVEIP, &CNetworkScannerDlg::OnBnClickedBtnScanRemoveip)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST_SCANRESULT, &CNetworkScannerDlg::OnListIPStatusCustomdraw)
	ON_WM_CLOSE()
	ON_NOTIFY(LVN_GETDISPINFO, IDC_LIST_SCANRESULT, &CNetworkScannerDlg::OnLvnGetdispinfoListScanresult)
	ON_BN_CLICKED(IDC_CHECK_HIDEDEADIP, &CNetworkScannerDlg::OnBnClickedCheckHidedeadip)
	ON_BN_CLICKED(IDC_BTN_SCAN_ADDIPFROMEXECL, &CNetworkScannerDlg::OnBnClickedBtnScanIPAddFromExcel)
	ON_BN_CLICKED(IDC_BTN_SCAN_EXPORTIP, &CNetworkScannerDlg::OnBnClickedBtnScanExportip)
	ON_NOTIFY(HDN_ITEMCLICKA, 0, &CNetworkScannerDlg::OnHdnItemClick)
	ON_NOTIFY(HDN_ITEMCLICKW, 0, &CNetworkScannerDlg::OnHdnItemClick)
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
	switch (m_ProgramState)
	{
		case SCANNIG_STATE::SCANNIG:
		case SCANNIG_STATE::SCANNING_ARPSEND:
		case SCANNIG_STATE::SCANNING_PINGSEND:
		case SCANNIG_STATE::SCANNING_SENDINGCOMPLETE:
			return;
		default:
			break;
	}
	m_ProgramState = SCANNIG_STATE::SCANNIG;
	// 버튼 클릭 제한
	// NIC 선택창
	CButton *btn = (CButton *)GetDlgItem(ID_BTN_NICDETAIL);
	btn->EnableWindow(FALSE);
	btn = (CButton *)GetDlgItem(ID_BTN_NICDETAIL);
	btn->EnableWindow(FALSE);

	// 콤보박스 클릭 제한
	m_ComboCtrlNICInfo.EnableWindow(FALSE);
	
	// 현재 선택된 인터페이스
	int nicindex = m_ComboCtrlNICInfo.GetCurSel();

	// 스캔 시작
	m_NetworkIPScan.Scan(nicindex);
	
}
void CNetworkScannerDlg::OnBnClickedBtnStopAll()
{
	// 프로그램 상태 변경
	m_ProgramState = SCANNIG_STATE::STOP_ALL;
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
	// 리스트 내용 초기화
	m_NetworkIPScan.GetIpStatusList()->ListInitForScan();

	ViewUpdate();
}
void CNetworkScannerDlg::OnBnClickedBtnStopSend()
{
	if (m_ProgramState == SCANNIG_STATE::STOP_RECV)
	{
		m_ProgramState = SCANNIG_STATE::STOP_ALL;
		m_NetworkIPScan.EndSend();
		CButton *btn = (CButton *)GetDlgItem(ID_BTN_NICDETAIL);
		btn->EnableWindow(TRUE);
		m_ComboCtrlNICInfo.EnableWindow(TRUE);
	}
	else if (m_ProgramState == SCANNIG_STATE::STOP_ALL)
		return;
	m_ProgramState = SCANNIG_STATE::STOP_SEND;
	m_NetworkIPScan.EndSend();
}

void CNetworkScannerDlg::OnBnClickedBtnNicdetail()
{
	// 모달로 실행
	int selected = m_NICInfoDlg.DoModal();
	if(selected != -1)
		m_ComboCtrlNICInfo.SetCurSel(selected);	
}
void CNetworkScannerDlg::OnBnClickedBtnScanAddip()
{
	CIPStatusList *iplist = m_NetworkIPScan.GetIpStatusList();
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
	
	m_NetworkIPScan.IPStatusListInsertItem(hbeginip, hendip);

	ViewUpdate();
	int size = iplist->GetSize();
	m_ListCtrlScanResult.SetItemCount(size);

}
void CNetworkScannerDlg::OnBnClickedBtnScanRemoveip()
{
	POSITION pos = m_ListCtrlScanResult.GetFirstSelectedItemPosition();
	int selected;
	while (pos)
	{
		selected = m_ListCtrlScanResult.GetNextSelectedItem(pos);
		int index = m_NetworkIPScan.GetIpStatusList()->IsInItem(m_ViewListBuffer.GetItem(selected)->IPAddress);
		if (index == -1)
			continue;
		else
		{
			m_NetworkIPScan.GetIpStatusList()->RemoveItem(index);
			m_ListCtrlScanResult.RedrawItems(selected - 1, selected + 1);
		}
	}
	ViewUpdate();
}


//--------------------------------------------------------------
// 초기화 함수들
//--------------------------------------------------------------
void CNetworkScannerDlg::InitializeAll()
{
	m_ProgramState = SCANNIG_STATE::BEGIN;
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
	shared_ptr<NICInfo> nicinfo;
	int size = nicinfolist->GetSize();
	char des[256];
	for (int i = 0; i < size; i++)
	{
		nicinfo = nicinfolist->At(i);
		memset(des, '\0', 256);
		memcpy(des, nicinfo->Description.data(), strlen(nicinfo->Description.data()));
		m_ComboCtrlNICInfo.AddString(CString(des));
	}
	
	m_ComboCtrlNICInfo.SetCurSel(0);
}

void CNetworkScannerDlg::IPAddrCtrlInit()
{
	u_long nicip, nicnetmask, nichostmask;
	u_long beginip, endip;

	CNICInfoList *list = m_NetworkIPScan.GetNicInfoList();
	int index = m_ComboCtrlNICInfo.GetCurSel();
	shared_ptr<NICInfo> nicinfo = list->At((index == -1) ? 1 : index);
	if (nicinfo != nullptr)
	{
		nicip = nicinfo->NICIPAddress;
		nicnetmask = nicinfo->Netmask;
		nichostmask = nicnetmask ^ 0xffffffff;
	}
	else
	{
		nicip = 0;
		nicnetmask = 0;
		nichostmask = nicnetmask ^ 0xffffffff;
	}
	

	// 네트워크 대역 검사
	beginip = nicip & nicnetmask;
	endip = beginip + nichostmask;

	u_char *casttemp1 = reinterpret_cast<u_char*>(&beginip);
	u_char *casttemp2 = reinterpret_cast<u_char*>(&endip);
	
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

// 리스트 컨트롤 초기화
void CNetworkScannerDlg::ListCtrlInit()
{
	static wchar_t *ListCtrlColumnString[] = {
		_T("No"),
		_T("IP Address"),
		_T("MAC Address"),
		_T("Ping Send Time"),
		_T("Ping Recv Time"),
		_T("IP Status"),
	};
	
	// View 스타일 설정
//	ListView_SetExtendedListViewStyle(m_ListCtrlScanResult.m_hWnd, LVS_EX_DOUBLEBUFFER| LVS_EX_FULLROWSELECT | LVS_EX_CHECKBOXES | LVS_EX_GRIDLINES);
	ListView_SetExtendedListViewStyle(m_ListCtrlScanResult.m_hWnd, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	// 열 설정
	int i = 0, size = sizeof(ListCtrlColumnString) / sizeof(wchar_t*);
	//m_ListCtrlScanResult.InsertColumn(i, LISTCTRL_COULMNSTRING(i++), LVCFMT_LEFT, 0, -1);
	m_ListCtrlScanResult.InsertColumn(i, ListCtrlColumnString[i++], LVCFMT_LEFT, LIST_COLUMN_NUMBER_LENGTH, -1);
	for (; i < size; i++)
		m_ListCtrlScanResult.InsertColumn(i, ListCtrlColumnString[i], LVCFMT_LEFT, LIST_COLUMN_LENGTH, -1);

	// 정렬 방향 초기화
	m_VectorColumnDirection.assign(size, false);
}

// 리스트 컨트롤 통지 함수(Customdraw)
afx_msg void CNetworkScannerDlg::OnListIPStatusCustomdraw(NMHDR* pNMHDR, LRESULT* pResult)
{
	IPSTATUS_CELLCOLOR__;		// static COLORREF ipstatcolor[] 선언

	NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);
	*pResult = CDRF_DODEFAULT;
	if (pLVCD->nmcd.dwDrawStage == CDDS_PREPAINT)
		*pResult = CDRF_NOTIFYITEMDRAW;
	else if (pLVCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
	{
		int nItem = static_cast<int>(pLVCD->nmcd.dwItemSpec);
		
		// 색 지정
		shared_ptr<IPStatusInfo> item = m_ViewListBuffer.GetItem(nItem);
		if (item == nullptr)
			return;
		pLVCD->clrTextBk = IPSTATUS_CELLCOLOR(item->IPStatus);
		*pResult = CDRF_DODEFAULT;
	}
}

// 리스트 컨트롤 버츄얼 리스트 적용
void CNetworkScannerDlg::OnLvnGetdispinfoListScanresult(NMHDR *pNMHDR, LRESULT *pResult)
{
	NMLVDISPINFO *pDispInfo = reinterpret_cast<NMLVDISPINFO*>(pNMHDR);

	// 출력용 스트링 변수 배열
	static wchar_t *ipstatstr[] =
	{
		TEXT("NOT USING"),
		TEXT("USING"),
		TEXT("GATEWAY"),
		TEXT("IP DUPLICATION"),
		TEXT("PING REPLY ONLY")
	};
	static uint8_t mactmp[6] = { 0, };

	CString str;
	shared_ptr<IPStatusInfo> ipstat;
	LV_ITEM* pItem = &(pDispInfo)->item;

	int index = pItem->iItem;
	ipstat = m_ViewListBuffer.GetItem(index);
	if (ipstat == nullptr)
		return;
	
	if (pItem->mask & LVIF_TEXT)
	{
		time_t local_tv_sec;
		struct tm *ltime;
		char timestr[16];
		switch (pItem->iSubItem)
		{
		case 0:	// 인덱스
			str.Format(_T("%d"), index + 1);
			lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
			break;
		case 1:	// ip
			str.Format(_T("%d.%d.%d.%d"), (ipstat->IPAddress) & 0xff, (ipstat->IPAddress >> 8) & 0xff, (ipstat->IPAddress >> 16) & 0xff, (ipstat->IPAddress >> 24) & 0xff);
			lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
			break;
		case 2: // MAC 주소
			if (m_ProgramState == SCANNIG_STATE::BEGIN)
				break;
			//if (strncmp((char*)ipstat->MACAddress, (char*)mactmp, MACADDRESS_LENGTH) == 0)
			//	break;
			str.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"), ipstat->MACAddress[0], ipstat->MACAddress[1], ipstat->MACAddress[2],
				ipstat->MACAddress[3], ipstat->MACAddress[4], ipstat->MACAddress[5]);
			lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
			break;
		case 3: // last ping send time
			if (m_ProgramState == SCANNIG_STATE::BEGIN)
				break;
			if (ipstat->LastPingSendTime.tv_sec == 0)
			{
				break;
			}
			else
			{
				local_tv_sec = ipstat->LastPingSendTime.tv_sec;
				ltime = localtime(&local_tv_sec);
				strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
			}
			str.Format(_T("%dH %dM %dS"), ltime->tm_hour, ltime->tm_min, ltime->tm_sec);
			lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
			break;
		case 4: // last ping recv time
			if (m_ProgramState == SCANNIG_STATE::BEGIN)
				break;
			if (ipstat->LastPingRecvTime.tv_sec == 0)
			{
				break;
			}
			else
			{
				local_tv_sec = ipstat->LastPingRecvTime.tv_sec;
				ltime = localtime(&local_tv_sec);
				strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
			}
			str.Format(_T("%dH %dM %dS"), ltime->tm_hour, ltime->tm_min, ltime->tm_sec);
			lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
			break;
		case 5: 
			if (m_ProgramState == SCANNIG_STATE::BEGIN)
				break;
			str.Format(ipstatstr[ipstat->IPStatus]);
			lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
			break;
		//case 6: ping 응답
		//	if (m_ProgramState == SCANNIG_STATE::BEGIN)
		//		break;
		//	str.Format(_T("%s"), ipstat->PingReply ? "O" : "X");
		//	lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
		//	break;
		default:
			break;
		}
	}
	if (pItem->mask & LVIF_IMAGE)
	{

	}
	*pResult = 0;
}
// 리스트 컨트롤 헤더 클릭 처리함수(정렬)
void CNetworkScannerDlg::OnHdnItemClick(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMHEADER phdr = reinterpret_cast<LPNMHEADER>(pNMHDR);

	int iSortColumn = phdr->iItem;
	
	CIPStatusList *captureitemlist = m_NetworkIPScan.GetIpStatusList();
	if (captureitemlist->Lock(INFINITE))
	{
		captureitemlist->Sort(iSortColumn, m_VectorColumnDirection[iSortColumn]);
		m_VectorColumnDirection[iSortColumn] = !m_VectorColumnDirection[iSortColumn];
	}
	captureitemlist->Unlock();

	ViewUpdate();
	return;
}

void CNetworkScannerDlg::StatusBarCtrlInit()
{
	m_StatusBarCtrl.Create(WS_CHILD | WS_VISIBLE | SBT_OWNERDRAW, CRect(0, 0, 0, 0), this, 0);
	CRect rect;
	GetClientRect(&rect);
	int strPartDim[2] = { rect.right / 2, -1 };
	m_StatusBarCtrl.SetParts(1, strPartDim);
	m_StatusBarCtrl.SetText(_T("Program Start. Scannig Available"), 0, 0);
	m_StatusBarCtrl.SetIcon(2, SetIcon(AfxGetApp()->LoadIcon(IDR_MAINFRAME), FALSE));
}
void CNetworkScannerDlg::StatusBarCtrlUpdate()
{
	STATUSBARCTRL_STRING__;
	StatusBarCtrlUpdate(STATUSBARCTRL_STRING(m_ProgramState));
}
void CNetworkScannerDlg::StatusBarCtrlUpdate(wchar_t* string)
{
	m_StatusBarCtrl.SetText(string, 0, 0);
}

void CNetworkScannerDlg::StartListUpdateThread()
{
	if (m_ListUpdateThread == NULL)
	{
		m_IsListUpdateThreadDye = false;
		m_ListUpdateThread = AfxBeginThread(ListUpdateThreadFunc, this, 0, 0, 0);
	}
	else
	{
		throw std::exception("list update thread 생성 실패");
	}
}
void CNetworkScannerDlg::EndListUpdateThread()
{
	if (m_ListUpdateThread != NULL)
	{
		Sleep(0);
		m_IsListUpdateThreadDye = true;
		WaitForSingleObject(m_ListUpdateThread, INFINITE);
		//Sleep(100);
		m_ListUpdateThread = NULL;
	}
}
UINT AFX_CDECL CNetworkScannerDlg::ListUpdateThreadFunc(LPVOID lpParam)
{
	CNetworkScannerDlg *maindlg = (CNetworkScannerDlg*)lpParam;
	CIPStatusList *iplist = &maindlg->m_ViewListBuffer;
	while (!maindlg->m_IsListUpdateThreadDye)
	{
		maindlg->StatusBarCtrlUpdate();
		maindlg->ViewUpdate();
		int size = iplist->GetSize();
		for (int i = 0; i < size; i++)
		{
			maindlg->m_ListCtrlScanResult.RedrawItems(i, i);
		}
		
		// 종료 메시지 확인
		for (int i = 0; i < 100; i++)
		{
			Sleep(10);
			if (maindlg->m_IsListUpdateThreadDye)
				break;
		}
	}
	return 0;
}

void CNetworkScannerDlg::UpdateListCtrl(int index)
{

}

void CNetworkScannerDlg::OnClose()
{
	m_ProgramState = SCANNIG_STATE::PROGRAM_END;
	// 쓰레드 중지
	EndListUpdateThread();
	m_NetworkIPScan.EndSend();
	m_NetworkIPScan.EndCapture();

	CDialogEx::OnClose();
}

void CNetworkScannerDlg::ViewUpdate()
{
	CIPStatusList *captureitemlist = m_NetworkIPScan.GetIpStatusList();
	shared_ptr<IPStatusInfo> ipstat;
	
	m_ViewListBuffer.ClearList();
	int size = captureitemlist->GetSize();
	
	for (int i = 0; i < size; i++)
	{
		ipstat = captureitemlist->GetItem(i);
		if (IsDlgButtonChecked(IDC_CHECK_HIDEDEADIP))
		{
			if (ipstat->IPStatus != IPSTATUS::NOTUSING)
				m_ViewListBuffer.AddItem(ipstat);
		}
		else
			m_ViewListBuffer.AddItem(ipstat);
	}
}

// Hide DeadIP 체크박스 클릭할 경우
void CNetworkScannerDlg::OnBnClickedCheckHidedeadip()
{
	ViewUpdate();
	m_ListCtrlScanResult.SetItemCount(m_ViewListBuffer.GetSize());
}


// IP Add From Excel 클릭 이벤트
void CNetworkScannerDlg::OnBnClickedBtnScanIPAddFromExcel()
{
	LPCTSTR szFilter = _T("Excel (*.csv)|*.csv|");
	CFileDialog dlg(true, L"csv", NULL, OFN_HIDEREADONLY | OFN_FILEMUSTEXIST, szFilter, this);
	CStdioFile csvFile;
	if (IDOK == dlg.DoModal())
	{
		CString strPathName = dlg.GetPathName();
		CString atrCheck = dlg.GetFileExt();
		CString line;
		if (atrCheck == _T("csv"))
		{
			if (!csvFile.Open(strPathName, CFile::modeNoTruncate | CFile::modeRead))
			{
				CString ErrMsg;
				ErrMsg.Format(L"[%s] 파일이 없습니다.", strPathName);
				MessageBox(ErrMsg);
				return;
			}

			while (csvFile.ReadString(line))
			{
				// csv file line parse
				int tok = line.Find(_T(","), 0);
				if (tok != -1)
					line = line.Left(tok);

				// List Add
				CW2AEX<256> WToA(line);
				u_long hip = inet_addr(WToA);
				hip = ntohl(inet_addr(WToA));
				m_NetworkIPScan.IPStatusListInsertItem(hip);
			}
			csvFile.Close();
		}
		else
		{
			MessageBox(_T("Not *.csv file"));
		}

		CIPStatusList *iplist = m_NetworkIPScan.GetIpStatusList();
		ViewUpdate();
		int size = iplist->GetSize();
		m_ListCtrlScanResult.SetItemCount(size);
	}
}

void CNetworkScannerDlg::OnBnClickedBtnScanExportip()
{
	CIPStatusList *iplist = m_NetworkIPScan.GetIpStatusList();
	LPCTSTR szFilter = _T("Excel (*.csv)|*.csv|");
	CFileDialog dlg(false, L"csv", NULL, NULL, szFilter, this);
	CStdioFile csvFile;

	if (IDOK == dlg.DoModal())
	{
		CString strPathName = dlg.GetPathName();
		CString extCheck = dlg.GetFileExt();
		
		if (extCheck == _T("csv"))
		{
			if (!csvFile.Open(strPathName, CFile::modeCreate | CFile::modeWrite))
			{
				MessageBox(_T("File Open Error"));
				return;
			}

			int itemSize = iplist->GetSize();
			shared_ptr<IPStatusInfo> item;
			CString line;
			in_addr ip;
			for (int i = 0; i < itemSize; i++)
			{
				item = iplist->GetItem(i);
				ip.s_addr = item->IPAddress;
				CA2WEX<> tmp(inet_ntoa(ip));
				line = tmp;
				csvFile.WriteString(line);
				csvFile.WriteString(L"\n");
			}
			csvFile.Close();
		}
		else
		{
			MessageBox(_T("Not *.csv file"));
		}
	}
}
