// NICInfoDlg.cpp : ���� �����Դϴ�.
//

#include "stdafx.h"
#include "NetworkScanner.h"
#include "NetworkScannerDlg.h"
#include "NICInfoDlg.h"
#include "afxdialogex.h"


// CNICInfoDlg ��ȭ �����Դϴ�.

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


// CNICInfoDlg �޽��� ó�����Դϴ�.

//------------------------------------------------------------------------
// �ڵ� ���� ��
//------------------------------------------------------------------------

//------------------------------------------------------------------------
// �ʱ�ȭ
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
	// static wchar_t *ListCtrlColumnString[] ����
	LISTCTRLNICINFO_COULMNSTRING;	

	m_ListCtrlNICInfoList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	// �� ����
	int i = 0, size = sizeof(ListCtrlColumnString) / sizeof(wchar_t*);
	m_ListCtrlNICInfoList.InsertColumn(i, ListCtrlColumnString[i], LVCFMT_LEFT, LIST_COLUMN_NUMBER_LENGTH, -1);
	i++;
	for (; i < size; i++)
		m_ListCtrlNICInfoList.InsertColumn(i, ListCtrlColumnString[i], LVCFMT_LEFT, LIST_COLUMN_LENGTH, -1);

	// Main Dlg ��������
	CNetworkScannerDlg *temp = (CNetworkScannerDlg*)AfxGetApp()->GetMainWnd();

	// nic list ��������: Network Scanner�� SendSocket�� �̿�
	CNICInfoList *niclist = temp->m_NetworkIPScan.GetNicInfoList();

	NICInfo *nicitem;
	CString str;
	size = niclist->GetSize();
	
	// NIC ���� ����
	// ����Ʈ ��Ʈ�� �ʱ�ȭ
	m_ListCtrlNICInfoList.DeleteAllItems();	
	// NIC ���� ���
	for (i = 0; i < size; i++)
	{
		nicitem = niclist->At(i);

		// 1��
		str.Format(_T("%d"), i + 1);
		m_ListCtrlNICInfoList.InsertItem(i, str);
		m_ListCtrlNICInfoList.SetItem(i, 1, LVIF_TEXT, CString(nicitem->Description), 0, 0, 0, NULL);

		// 2��
		str.Format(_T("%d.%d.%d.%d"),
			(nicitem->NICIPAddress) & 0xff,
			(nicitem->NICIPAddress >> 8) & 0xff,
			(nicitem->NICIPAddress >> 16) & 0xff,
			(nicitem->NICIPAddress >> 24) & 0xff);
		m_ListCtrlNICInfoList.SetItem(i, 2, LVIF_TEXT, str, 0, 0, 0, NULL);

		// 3��
		str.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"), 
			nicitem->NICMACAddress[0],
			nicitem->NICMACAddress[1], 
			nicitem->NICMACAddress[2], 
			nicitem->NICMACAddress[3], 
			nicitem->NICMACAddress[4], 
			nicitem->NICMACAddress[5] );
		m_ListCtrlNICInfoList.SetItem(i, 3, LVIF_TEXT, str, 0, 0, 0, NULL);

		// 4��
		str.Format(_T("%d.%d.%d.%d"),
			(nicitem->Netmask) & 0xff,
			(nicitem->Netmask >> 8) & 0xff,
			(nicitem->Netmask >> 16) & 0xff,
			(nicitem->Netmask >> 24) & 0xff);
		m_ListCtrlNICInfoList.SetItem(i, 4, LVIF_TEXT, str, 0, 0, 0, NULL);
	}
}

//------------------------------------------------------------------------
// �ڵ� ���� ��
//------------------------------------------------------------------------

void CNICInfoDlg::OnBnClickedBtnSelect()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
	int selected = -1;

	POSITION pos = m_ListCtrlNICInfoList.GetFirstSelectedItemPosition();
	while (pos)
	{
		selected = m_ListCtrlNICInfoList.GetNextSelectedItem(pos);
		break;
	}

	// ���� ���� ��� 0�� ����
	if (selected == -1)
	{
		AfxMessageBox(_T("�ϳ��� ������ �ּ���."));
		return;
	}
	// ���õ� NIC ��ȯ
	this->EndModalLoop(selected);
}

void CNICInfoDlg::OnBnClickedCancel()
{
	// TODO: ���⿡ ��Ʈ�� �˸� ó���� �ڵ带 �߰��մϴ�.
	// CDialogEx::OnCancel();
	this->EndModalLoop(-1);
}
