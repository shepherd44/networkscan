
// NetworkScanner_v1.0Dlg.cpp : ���� ����
//

#include "stdafx.h"
//#include "NetworkScanner.h"
//#include "NetworkScannerDlg.h"
#include "afxdialogex.h"
#include "NetworkScannerDlg.h"

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
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST_SCANRESULT, &CNetworkScannerDlg::OnListIPStatusCustomdraw)
	ON_WM_CLOSE()
	ON_NOTIFY(LVN_GETDISPINFO, IDC_LIST_SCANRESULT, &CNetworkScannerDlg::OnLvnGetdispinfoListScanresult)
	ON_BN_CLICKED(IDC_CHECK_HIDEDEADIP, &CNetworkScannerDlg::OnBnClickedCheckHidedeadip)
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
	m_ProgramState = SCANNIG_STATE::SCANNIG;
	// ��ư Ŭ�� ����
	// NIC ����â
	CButton *btn = (CButton *)GetDlgItem(ID_BTN_NICDETAIL);
	btn->EnableWindow(FALSE);
	btn = (CButton *)GetDlgItem(ID_BTN_NICDETAIL);
	btn->EnableWindow(FALSE);

	// �޺��ڽ� Ŭ�� ����
	m_ComboCtrlNICInfo.EnableWindow(FALSE);
	
	// ���� ���õ� �������̽�
	int nicindex = m_ComboCtrlNICInfo.GetCurSel();

	// ��ĵ ����
	m_NetworkIPScan.Scan(nicindex);
}
void CNetworkScannerDlg::OnBnClickedBtnStopAll()
{
	// ���α׷� ���� ����
	m_ProgramState = SCANNIG_STATE::STOP_ALL;
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
	m_ProgramState = SCANNIG_STATE::STOP_SEND;
	m_NetworkIPScan.EndSend();
}
void CNetworkScannerDlg::OnBnClickedBtnStopRecv()
{
	m_ProgramState = SCANNIG_STATE::STOP_RECV;
	m_NetworkIPScan.EndCapture();
}
// NIC Information �ڼ��� ���� ��ư ó��
void CNetworkScannerDlg::OnBnClickedBtnNicdetail()
{
	// ��޷� ����
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
		AfxMessageBox(_T("IP ������ �ݴ�� �Է��Ͽ����ϴ�."));
		return;
	}
	
	m_NetworkIPScan.IPStatusListInsertItem(hbeginip, hendip);

	int size = iplist->GetSize();

	ViewUpdate();
	m_ListCtrlScanResult.SetItemCount(size);
}
void CNetworkScannerDlg::OnBnClickedBtnScanRemoveip()
{
	POSITION pos = m_ListCtrlScanResult.GetFirstSelectedItemPosition();
	int selected;
	IPStatusInfo *ipstat;
	while (pos)
	{
		selected = m_ListCtrlScanResult.GetNextSelectedItem(pos);
		int index = m_NetworkIPScan.GetIpStatusList()->IsInItem(m_ViewListBuffer.At(selected)->IPAddress);
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
// �ʱ�ȭ �Լ���
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

// ����Ʈ ��Ʈ�� �ʱ�ȭ
void CNetworkScannerDlg::ListCtrlInit()
{
	LISTCTRL_COULMNSTRING__;	// static wchar_t *ListCtrlColumnString[] ����
	
	ListView_SetExtendedListViewStyle(m_ListCtrlScanResult.m_hWnd, LVS_EX_DOUBLEBUFFER| LVS_EX_FULLROWSELECT | LVS_EX_CHECKBOXES | LVS_EX_GRIDLINES);
	
	// �� ����
	int i = 0, size = sizeof(LISTCTRL_COULMNSTRING_) / sizeof(wchar_t*);
	m_ListCtrlScanResult.InsertColumn(i, LISTCTRL_COULMNSTRING(i++), LVCFMT_LEFT, 0, -1);
	m_ListCtrlScanResult.InsertColumn(i, LISTCTRL_COULMNSTRING(i++), LVCFMT_LEFT, LIST_COLUMN_NUMBER_LENGTH, -1);
	for (; i < size; i++)
		m_ListCtrlScanResult.InsertColumn(i, ListCtrlColumnString[i], LVCFMT_LEFT, LIST_COLUMN_LENGTH, -1);
}

// ����Ʈ ��Ʈ�� ���� �Լ�(Customdraw)
afx_msg void CNetworkScannerDlg::OnListIPStatusCustomdraw(NMHDR* pNMHDR, LRESULT* pResult)
{
	IPSTATUS_CELLCOLOR__;		// static COLORREF ipstatcolor[] ����

	NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);
	*pResult = CDRF_DODEFAULT;
	if (pLVCD->nmcd.dwDrawStage == CDDS_PREPAINT)
		*pResult = CDRF_NOTIFYITEMDRAW;
	else if (pLVCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
	{
		int nItem = static_cast<int>(pLVCD->nmcd.dwItemSpec);
		
		// �� ����
		IPStatusInfo *item = m_ViewListBuffer.At(nItem);
		pLVCD->clrTextBk = IPSTATUS_CELLCOLOR(item->IPStatus);
		*pResult = CDRF_DODEFAULT;
	}
}

// ����Ʈ ��Ʈ�� ����� ����Ʈ ����
void CNetworkScannerDlg::OnLvnGetdispinfoListScanresult(NMHDR *pNMHDR, LRESULT *pResult)
{
	NMLVDISPINFO *pDispInfo = reinterpret_cast<NMLVDISPINFO*>(pNMHDR);

	// ��¿� ��Ʈ�� ���� �迭
	static wchar_t *ipstatstr[] =
	{
		TEXT("NOT USING"),
		TEXT("USING"),
		TEXT("GATEWAY"),
		TEXT("IP DUPLICATION"),
		TEXT("PING REPLY ONLY")
	};

	CString str;
	IPStatusInfo *ipstat;
	LV_ITEM* pItem = &(pDispInfo)->item;

	int index = pItem->iItem;
	ipstat = m_ViewListBuffer.At(index);
	if (pItem->mask & LVIF_TEXT)
	{
		switch (pItem->iSubItem)
		{
		case 0:
			break;
		case 1:	// �ε���
			str.Format(_T("%d"), index + 1);
			lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
			break;
		case 2:	// ip
			str.Format(_T("%d.%d.%d.%d"), (ipstat->IPAddress) & 0xff, (ipstat->IPAddress >> 8) & 0xff, (ipstat->IPAddress >> 16) & 0xff, (ipstat->IPAddress >> 24) & 0xff);
			lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
			break;
		case 3:
			str.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"), ipstat->MACAddress[0], ipstat->MACAddress[1], ipstat->MACAddress[2],
				ipstat->MACAddress[3], ipstat->MACAddress[4], ipstat->MACAddress[5]);
			lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
			break;
		case 4:
			str.Format(ipstatstr[ipstat->IPStatus]);
			lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
			break;
		case 5:
			str.Format(_T("%s"), ipstat->PingReply ? "O" : "X");
			lstrcpyn(pItem->pszText, str, pItem->cchTextMax);
			break;
		default:
			break;
		}
	}
	if (pItem->mask & LVIF_IMAGE)
	{

	}
	*pResult = 0;
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
		throw std::exception("list update thread ���� ����");
	}
}
void CNetworkScannerDlg::EndListUpdateThread()
{
	if (m_ListUpdateThread != NULL)
	{
		m_IsListUpdateThreadDye = true;
		WaitForSingleObject(m_ListUpdateThread, INFINITE);
		Sleep(100);
		m_ListUpdateThread = NULL;
	}
}
UINT AFX_CDECL CNetworkScannerDlg::ListUpdateThreadFunc(LPVOID lpParam)
{
	CNetworkScannerDlg *maindlg = (CNetworkScannerDlg*)lpParam;
	CIPStatusList *iplist = &maindlg->m_ViewListBuffer;
	while (1)
	{
		if (maindlg->m_IsListUpdateThreadDye)
			break;

		maindlg->StatusBarCtrlUpdate();
		maindlg->ViewUpdate();
		int size = iplist->GetSize();
		for (int i = 0; i < size; i++)
		{
			maindlg->m_ListCtrlScanResult.RedrawItems(i,i);
		}
		
		
		// ���� �޽��� Ȯ��
		for (int i = 0; i < 10; i++)
		{
			Sleep(100);
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
	// ������ ����
	m_NetworkIPScan.EndSend();
	m_NetworkIPScan.EndCapture();
	EndListUpdateThread();

	CDialogEx::OnClose();
}

void CNetworkScannerDlg::ViewUpdate()
{
	CIPStatusList *captureitemlist = m_NetworkIPScan.GetIpStatusList();
	IPStatusInfo *ipstat;
	int size = captureitemlist->GetSize();
	
	m_ViewListBuffer.ClearList();
	if (IsDlgButtonChecked(IDC_CHECK_HIDEDEADIP))
	{
		for (int i = 0; i < size; i++)
		{
			ipstat = captureitemlist->At(i);
			if (ipstat->IPStatus != IPSTATUS::NOTUSING)
				m_ViewListBuffer.AddItem(ipstat->IPAddress, ipstat->MACAddress, ipstat->IPStatus, ipstat->PingReply);
		}
	}
	else
	{
		for (int i = 0; i < size; i++)
		{
			ipstat = captureitemlist->At(i);
			m_ViewListBuffer.AddItem(ipstat->IPAddress, ipstat->MACAddress, ipstat->IPStatus, ipstat->PingReply);
		}
	}
}

// Hide DeadIP üũ�ڽ� Ŭ���� ���
void CNetworkScannerDlg::OnBnClickedCheckHidedeadip()
{
	ViewUpdate();
	m_ListCtrlScanResult.SetItemCount(m_ViewListBuffer.GetSize());
}
