
// NetworkScanner_v1.0Dlg.cpp : ���� ����
//

#include "stdafx.h"
#include "NetworkScanner.h"
#include "NetworkScannerDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ���� ���α׷� ������ ���Ǵ� CAboutDlg ��ȭ �����Դϴ�.

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// ��ȭ ���� �������Դϴ�.
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV �����Դϴ�.

// �����Դϴ�.
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


// CNetworkScannerDlg ��ȭ ����


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


// CNetworkScannerDlg �޽��� ó����

BOOL CNetworkScannerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// �ý��� �޴��� "����..." �޴� �׸��� �߰��մϴ�.

	// IDM_ABOUTBOX�� �ý��� ��� ������ �־�� �մϴ�.
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

	// �� ��ȭ ������ �������� �����մϴ�.  ���� ���α׷��� �� â�� ��ȭ ���ڰ� �ƴ� ��쿡��
	//  �����ӿ�ũ�� �� �۾��� �ڵ����� �����մϴ�.
	SetIcon(m_hIcon, TRUE);			// ū �������� �����մϴ�.
	SetIcon(m_hIcon, FALSE);		// ���� �������� �����մϴ�.

	// TODO: ���⿡ �߰� �ʱ�ȭ �۾��� �߰��մϴ�.
	InitializeAll();


	return TRUE;  // ��Ŀ���� ��Ʈ�ѿ� �������� ������ TRUE�� ��ȯ�մϴ�.
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

// ��ȭ ���ڿ� �ּ�ȭ ���߸� �߰��� ��� �������� �׸�����
//  �Ʒ� �ڵ尡 �ʿ��մϴ�.  ����/�� ���� ����ϴ� MFC ���� ���α׷��� ��쿡��
//  �����ӿ�ũ���� �� �۾��� �ڵ����� �����մϴ�.

void CNetworkScannerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // �׸��⸦ ���� ����̽� ���ؽ�Ʈ�Դϴ�.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Ŭ���̾�Ʈ �簢������ �������� ����� ����ϴ�.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// �������� �׸��ϴ�.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// ����ڰ� �ּ�ȭ�� â�� ���� ���ȿ� Ŀ���� ǥ�õǵ��� �ý��ۿ���
//  �� �Լ��� ȣ���մϴ�.
HCURSOR CNetworkScannerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//--------------------------------------------------------------
// �ڵ� ���� �Լ� ��
//--------------------------------------------------------------

//--------------------------------------------------------------
// ��ư Ŭ�� ó�� �̺�Ʈ �Լ�
//--------------------------------------------------------------

void CNetworkScannerDlg::OnBnClickedBtnScan()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
	
	// ��ư Ŭ�� ����
	CButton *btn = (CButton *)GetDlgItem(ID_BTN_NICDETAIL);
	btn->EnableWindow(FALSE);
	// �޺��ڽ� Ŭ�� ����
	m_ComboCtrlNICInfo.EnableWindow(FALSE);
	
	// 
	int nicindex = m_ComboCtrlNICInfo.GetCurSel();

	// ��ĵ ����
	m_NetworkIPScan.Scan(nicindex);

}

void CNetworkScannerDlg::OnBnClickedBtnStopAll()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.

	// ��Ŷ ���� ������ ����
	m_NetworkIPScan.EndSend();
	// ��Ŷ ĸó ������ ����
	m_NetworkIPScan.EndCapture();
	// ��Ʈ�� Ȱ��ȭ
	// ��ư Ŭ�� ����
	CButton *btn = (CButton *)GetDlgItem(ID_BTN_NICDETAIL);
	btn->EnableWindow(TRUE);
	// �޺��ڽ� Ŭ�� ����
	m_ComboCtrlNICInfo.EnableWindow(TRUE);
}

void CNetworkScannerDlg::OnBnClickedBtnStopSend()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
}

void CNetworkScannerDlg::OnBnClickedBtnStopRecv()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
}

// NIC Information �ڼ��� ����
void CNetworkScannerDlg::OnBnClickedBtnNicdetail()
{
	// ��޷� ����
	int selected = m_NICInfoDlg.DoModal();
	if(selected != -1)
		m_ComboCtrlNICInfo.SetCurSel(selected);	
}

void CNetworkScannerDlg::OnBnClickedBtnScanAddip()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
	u_long hbeginip, hendip;
	uint8_t mac[MACADDRESS_LENGTH];
	memset(mac, 0, MACADDRESS_LENGTH);
	m_IPAddrCtrlBeginIP.GetAddress(hbeginip);
	m_IPAddrCtrlEndIP.GetAddress(hendip);

	if (hbeginip > hendip)
	{
		AfxMessageBox(_T("IP ������ �ݴ�� �Է��Ͽ����ϴ�."));
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
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
	int count = m_ListCtrlScanResult.GetItemCount();
	for (int i = 0; i < count; i++)
	{
		BOOL a = m_ListCtrlScanResult.GetCheck(i);
		if (a == TRUE)
		{
			CString temp = m_ListCtrlScanResult.GetItemText(i, 0);
			temp.Format(_T("%s seq�� ���õ�"), temp);
			AfxMessageBox(temp);
		}
	}
}


//--------------------------------------------------------------
// �ʱ�ȭ �Լ���
//--------------------------------------------------------------
void CNetworkScannerDlg::InitializeAll()
{
	ListCtrlInit();
	IPAddrCtrlInit();
	StatusBarCtrlInit();
	ComboBoxInit();
	m_ListUpdateThread = NULL;
	StartListUpdateThread();
	// ����Ʈ ��Ʈ�� ui ������ ���� �߰�
}

// NIC ���� �޺� �ڽ�
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

// ����Ʈ ��Ʈ�� �ʱ�ȭ
void CNetworkScannerDlg::ListCtrlInit()
{
	LISTCTRL_COULMNSTRING;	// static wchar_t *ListCtrlColumnString[] ����
	ListCtrlDeleteAll();
	
	// üũ�ڽ� üũ���
	// SetCheck(i, false)
	m_ListCtrlScanResult.SetExtendedStyle(LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	// �� ����
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

// IP �Է� ��Ʈ�� �ʱ�ȭ
void CNetworkScannerDlg::IPAddrCtrlInit()
{
	u_long nicip, nicnetmask, nichostmask;
	u_long beginip, endip;

	CNICInfoList *list = m_NetworkIPScan.GetNicInfoList();
	NICInfo *nicinfo = list->At(m_ComboCtrlNICInfo.GetCurSel());
	nicip = nicinfo->NICIPAddress;
	nicnetmask = nicinfo->Netmask;
	nichostmask = nicnetmask ^ 0xffffffff;

	// ��Ʈ��ũ �뿪 �˻�
	beginip = nicip & nicnetmask;
	endip = beginip + nichostmask;

	u_char *casttemp1 = reinterpret_cast<u_char*>(&beginip);
	u_char *casttemp2 = reinterpret_cast<u_char*>(&endip);
	// Begin IP input ���� ����
	m_IPAddrCtrlBeginIP.SetFieldRange(0, static_cast<char>(casttemp1[0]), static_cast<char>(casttemp2[0]));
	m_IPAddrCtrlBeginIP.SetFieldRange(1, static_cast<char>(casttemp1[1]), static_cast<char>(casttemp2[1]));
	//m_IPAddrCtrlBeginIP.SetFieldRange(2, static_cast<char>(casttemp1[2]), static_cast<char>(casttemp2[2]));
	//m_IPAddrCtrlBeginIP.SetFieldRange(3, static_cast<char>(casttemp1[3]), static_cast<char>(casttemp2[3]));

	// End IP input ���� ����
	m_IPAddrCtrlEndIP.SetFieldRange(0, static_cast<char>(casttemp1[0]), static_cast<char>(casttemp2[0]));
	m_IPAddrCtrlEndIP.SetFieldRange(1, static_cast<char>(casttemp1[1]), static_cast<char>(casttemp2[1]));
	//m_IPAddrCtrlEndIP.SetFieldRange(2, static_cast<char>(casttemp1[2]), static_cast<char>(casttemp2[2]));
	//m_IPAddrCtrlEndIP.SetFieldRange(3, static_cast<char>(casttemp1[3]), static_cast<char>(casttemp2[3]));

	// ù �ּ� ����
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
	// ��¿� ��Ʈ�� ���� �迭
	static wchar_t *ipstatstr[] =
	{
		TEXT("NOT USING"),
		TEXT("USING"),
		TEXT("GATEWAY"),
		TEXT("IP DUPLICATION"),
	};
	
	CString str;
	int index = m_ListCtrlScanResult.GetItemCount();
	// 1�� üũ�ڽ�
	m_ListCtrlScanResult.InsertItem(index, str);

	// 2�� ��ȣ
	str.Format(_T("%d"), index + 1);
	m_ListCtrlScanResult.SetItem(index, 1, LVIF_TEXT, str, 0, 0, 0, NULL);

	// 3�� IP Address ����
	str.Format(_T("%d.%d.%d.%d"), (item->IPAddress) & 0xff, (item->IPAddress >> 8) & 0xff, (item->IPAddress >> 16) & 0xff, (item->IPAddress >> 24) & 0xff);
	m_ListCtrlScanResult.SetItem(index, 2, LVIF_TEXT, str, 0, 0, 0, NULL);

	// 4�� MAC  ����
	str.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"), item->MACAddress[0], item->MACAddress[1], item->MACAddress[2], 
		item->MACAddress[3], item->MACAddress[4], item->MACAddress[5]);
	m_ListCtrlScanResult.SetItem(index, 3, LVIF_TEXT, str, 0, 0, 0, NULL);

	// 5�� IP Status ����
	str.Format(ipstatstr[item->IPStatus]);
	m_ListCtrlScanResult.SetItem(index, 4, LVIF_TEXT, str, 0, 0, 0, NULL);

	// 6�� Ping
	str.Format(_T("%s"), item->PingReply ? "O" :"X");
	m_ListCtrlScanResult.SetItem(index, 5, LVIF_TEXT, str, 0, 0, 0, NULL);
}

// ����Ʈ ��Ʈ�� ���� �Լ�
afx_msg void CNetworkScannerDlg::OnListIPStatusCustomdraw(NMHDR* pNMHDR, LRESULT* pResult)
{
	IPSTATUS_CELLCOLOR;		// static COLORREF ipstatcolor[] ����

	NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);
	*pResult = CDRF_DODEFAULT;
	if (pLVCD->nmcd.dwDrawStage == CDDS_PREPAINT)
		*pResult = CDRF_NOTIFYITEMDRAW;
	else if (pLVCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
	{
		int nItem = static_cast<int>(pLVCD->nmcd.dwItemSpec);
		// �� ����
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
		throw std::exception("list update thread ���� ����");
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

		// ������ ���� Ȯ��
		if (isdye)
			break;
	}
	return 0;
}