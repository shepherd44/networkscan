
// IPScannerDlg.cpp : ���� ����
//

#include "stdafx.h"
#include "IPScanner.h"
#include "IPScannerDlg.h"
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


// CIPScannerDlg ��ȭ ����



CIPScannerDlg::CIPScannerDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CIPScannerDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

// ��Ʈ�� - ��� ���� ����
void CIPScannerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_IPADDRESS_BEGINIP, m_IPAddressBeginIP);
	DDX_Control(pDX, IDC_IPADDRESS_ENDIP, m_IPAddressEndIP);
	DDX_Control(pDX, IDC_LIST_IPStatus, m_ListIPStatus);
}

// �޽��� ��
BEGIN_MESSAGE_MAP(CIPScannerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(ID_BTN_SCAN, &CIPScannerDlg::OnBnClickedBtnScan)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST_IPStatus, CIPScannerDlg::OnListIPStatusCustomdraw)
END_MESSAGE_MAP()


// CIPScannerDlg �޽��� ó����

BOOL CIPScannerDlg::OnInitDialog()
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

// ��ȭ ���ڿ� �ּ�ȭ ���߸� �߰��� ��� �������� �׸�����
//  �Ʒ� �ڵ尡 �ʿ��մϴ�.  ����/�� ���� ����ϴ� MFC ���� ���α׷��� ��쿡��
//  �����ӿ�ũ���� �� �۾��� �ڵ����� �����մϴ�.

void CIPScannerDlg::OnPaint()
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
HCURSOR CIPScannerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

// �ڵ� ���� �Լ� ��
//--------------------------------------------------------------------------------
// ����Ʈ ��Ʈ�� ���� �Լ�
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

// Scan ��ư Ŭ�� �̺�Ʈ ó����
void CIPScannerDlg::OnBnClickedBtnScan()
{
	// �Էµ� IP �ּ� ó��
	u_long beginip, endip;
	u_long size = 0;
	m_IPAddressBeginIP.GetAddress(beginip);
	m_IPAddressEndIP.GetAddress(endip);

	// �Է� ���� üũ
	if (beginip > endip)
	{
		AfxMessageBox(_T("IP ������ �ݴ�� �Է��Ͽ����ϴ�."));
		return;
	}

	// ��ĵ ����
	m_networkIPScanner.Scan(beginip, endip);
	// ���
	Display();
}

// �ʱ�ȭ �Լ�
void CIPScannerDlg::InitializeAll()
{
	HANDLE m_hCaptureThread = NULL;
	ListCtrlInit();
	IPAddressCtrlInit();
}

// ����Ʈ ��Ʈ�� �ʱ�ȭ
void CIPScannerDlg::ListCtrlInit()
{
	ListCtrlDeleteAll();
	m_ListIPStatus.SetExtendedStyle(LVS_EX_GRIDLINES);

	// �� ����
	m_ListIPStatus.InsertColumn(0, _T("IP Address"), LVCFMT_LEFT, 140, -1);
	m_ListIPStatus.InsertColumn(1, _T("IP Status"), LVCFMT_LEFT, 140, -1);
	m_ListIPStatus.InsertColumn(2, _T("MAC Address"), LVCFMT_LEFT, 140, -1);
}

// ����Ʈ ��Ʈ�� ������ ����
void CIPScannerDlg::ListCtrlInsertData(IPStatusInfo *ipstat)
{
	// ��¿� ��Ʈ�� ���� �迭
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
	
	// 1�� IP Address ����
	str.Format(TEXT("%d.%d.%d.%d"), ucptemp[0], ucptemp[1], ucptemp[2], ucptemp[3]);
	int index = m_ListIPStatus.GetItemCount();
	m_ListIPStatus.InsertItem(index, str);

	// 2�� IP Status ����
	str.Format(TEXT("%s"), ipstatstr[ipstat->m_IPStatus]);
	m_ListIPStatus.SetItem(index, 1, LVIF_TEXT, str, 0, 0, 0, NULL);
	
	// 3�� MAC Address ����
	ucptemp = reinterpret_cast<u_char*>(&ipstat->m_MACAddress);
	str.Format(TEXT("%02X:%02X:%02X:%02X:%02X:%02X"), ucptemp[0], ucptemp[1], ucptemp[2],
												ucptemp[3], ucptemp[4], ucptemp[5]);
	m_ListIPStatus.SetItem(index, 2, LVIF_TEXT, str, 0, 0, 0, NULL);
}

// ����Ʈ ��Ʈ�� ���� ����
void CIPScannerDlg::ListCtrlDeleteAll()
{
	m_ListIPStatus.DeleteAllItems();
}

// IPAddr ��Ʈ�� �ʱ�ȭ
void CIPScannerDlg::IPAddressCtrlInit()
{
	u_long nicip, nicnetmask, nichostmask;
	u_long beginip, endip;

	memcpy(&nicip, m_networkIPScanner.GetNICIPAddress(), IPV4ADDRESSLENGTH);
	memcpy(&nicnetmask, m_networkIPScanner.GetNICNetmask(), IPV4ADDRESSLENGTH);
	nichostmask = nicnetmask ^ 0xffffffff;
	
	// ��Ʈ��ũ �뿪 �˻�
	beginip = nicip & nicnetmask;
	endip = beginip + nichostmask;

	u_char *casttemp1 = reinterpret_cast<u_char*>(&beginip);
	u_char *casttemp2 = reinterpret_cast<u_char*>(&endip);
	// Begin IP input ���� ����
	m_IPAddressBeginIP.SetFieldRange(0, static_cast<char>(casttemp1[0]), static_cast<char>(casttemp2[0]));
	m_IPAddressBeginIP.SetFieldRange(1, static_cast<char>(casttemp1[1]), static_cast<char>(casttemp2[1]));
	m_IPAddressBeginIP.SetFieldRange(2, static_cast<char>(casttemp1[2]), static_cast<char>(casttemp2[2]));
	m_IPAddressBeginIP.SetFieldRange(3, static_cast<char>(casttemp1[3]), static_cast<char>(casttemp2[3]));

	// End IP input ���� ����
	m_IPAddressEndIP.SetFieldRange(0, static_cast<char>(casttemp1[0]), static_cast<char>(casttemp2[0]));
	m_IPAddressEndIP.SetFieldRange(1, static_cast<char>(casttemp1[1]), static_cast<char>(casttemp2[1]));
	m_IPAddressEndIP.SetFieldRange(2, static_cast<char>(casttemp1[2]), static_cast<char>(casttemp2[2]));
	m_IPAddressEndIP.SetFieldRange(3, static_cast<char>(casttemp1[3]), static_cast<char>(casttemp2[3]));

	// ù �ּ� ����
	m_IPAddressBeginIP.SetAddress(static_cast<char>(casttemp1[0]),
								  static_cast<char>(casttemp1[1]),
								  static_cast<char>(casttemp1[2]),
								  static_cast<char>(casttemp1[3]) + 1);
	m_IPAddressEndIP.SetAddress(static_cast<char>(casttemp2[0]),
								static_cast<char>(casttemp2[1]),
								static_cast<char>(casttemp2[2]),
								static_cast<char>(casttemp2[3]) - 1);
}

// ��� ����Ʈ ��Ʈ�ѷ� �ݿ�
void CIPScannerDlg::Display()
{
	// ����Ʈ ��Ʈ�� ����
	ListCtrlDeleteAll();
	// ��� ����Ʈ ��Ʈ�ѿ� ����
	int vecend = m_networkIPScanner.GetIPStatusVector().GetSize();
	for (int i = 0; i < vecend; i++)
		ListCtrlInsertData(&m_networkIPScanner[i]);
}