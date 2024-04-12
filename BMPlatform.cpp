#include "BMPlatform.h"
#include <iostream>
extern "C" { extern int m_bOpened; }

CBMPlatformApp::CBMPlatformApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
	m_pfCreateChannel = NULL;
	m_pfReleaseChannel = NULL;
	m_hChannelLib = NULL;
}

BOOL CBMPlatformApp::InitInstance()
{
	m_hChannelLib = LoadLibrary(_T("Channel9.dll"));

	if(m_hChannelLib == NULL)
	{
		std::cout << GetLastError() << std::endl;
		return FALSE;
	}

	m_pfCreateChannel = (pfCreateChannel)GetProcAddress(m_hChannelLib,"CreateChannel");
	m_pfReleaseChannel = (pfReleaseChannel)GetProcAddress(m_hChannelLib,"ReleaseChannel");

	if(m_pfCreateChannel == NULL || m_pfReleaseChannel == NULL )
	{
		return FALSE;
	}

	return TRUE;
}

int CBMPlatformApp::ExitInstance()
{
	// TODO: Add your specialized code here and/or call the base class
	if(m_hChannelLib)
	{
		FreeLibrary(m_hChannelLib);
		m_hChannelLib = NULL;

		//m_pfCreateChannel = NULL;
		//m_pfReleaseChannel = NULL;
	}

	return TRUE;
}

CBMPlatformApp g_theApp;

CBootModeOpr::CBootModeOpr()
{
	m_pChannel = NULL;
	g_theApp.InitInstance();
}

CBootModeOpr::~CBootModeOpr()
{
	g_theApp.ExitInstance();
}

BOOL CBootModeOpr::Initialize()
{
	if (!g_theApp.m_pfCreateChannel)
	{
		return FALSE;
	}
	if (!g_theApp.m_pfCreateChannel((ICommChannel**)&m_pChannel, CHANNEL_TYPE_COM))
	{
		return FALSE;
	}
	return TRUE;
}

void CBootModeOpr::Uninitialize()
{
	if (m_pChannel)
	{
		if (g_theApp.m_pfReleaseChannel)
			g_theApp.m_pfReleaseChannel(m_pChannel);
		m_pChannel = NULL;
	}
}

int CBootModeOpr::Read(UCHAR * m_RecvData, int max_len, int dwTimeout)
{
	if (!m_bOpened) return -1;
	ULONGLONG tBegin;
	ULONGLONG tCur;
	tBegin = GetTickCount64();
	do
	{
		tCur = GetTickCount64();
		DWORD dwRead = m_pChannel->Read(m_RecvData, max_len, dwTimeout);
		if (dwRead)
		{
			return dwRead;
		}
	} while ((tCur - tBegin) < dwTimeout);
	return 0;
}

int CBootModeOpr::Write(UCHAR* lpData, int iDataSize)
{
	if (!m_bOpened) return -1;
	return m_pChannel->Write(lpData, iDataSize);
}

BOOL CBootModeOpr::GetProperty(LONG lFlags, DWORD dwPropertyID, LPVOID pValue)
{
	return m_pChannel->GetProperty(lFlags, dwPropertyID, pValue);
}

BOOL CBootModeOpr::SetProperty(LONG lFlags, DWORD dwPropertyID, LPCVOID pValue)
{
	return m_pChannel->SetProperty(lFlags, dwPropertyID, pValue);
}

BOOL CBootModeOpr::ConnectChannel(DWORD dwPort)
{
	if (m_pChannel == NULL)
	{
		return FALSE;
	}

	if(!dwPort) return FALSE;

	CHANNEL_ATTRIBUTE ca;
	ca.ChannelType = CHANNEL_TYPE_COM;
	ca.Com.dwPortNum = dwPort;
	ca.Com.dwBaudRate = 115200;

	//Log(_T("Connect Channel +++"));
	m_bOpened = m_pChannel->Open(&ca);
	//Log(_T("Connect Channel ---"));
	return m_bOpened;
}

BOOL CBootModeOpr::DisconnectChannel()
{
	if (m_pChannel == NULL)
	{
		return FALSE;
	}

	if (m_bOpened)
	{
		m_bOpened = 0;
		//Log(_T("Disconnect Channel +++"));
		m_pChannel->Close();
		//Log(_T("Disconnect Channel ---"));
	}
	return TRUE;
}
