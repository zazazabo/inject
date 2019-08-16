#pragma once
#include "stdafx.h"
#include <windows.h>
#include <string>
#include <map>

using namespace std;
;




class CFrameWnd : public WindowImplBase
{
public:
  CFrameWnd(LPCTSTR pszXMLPath);
  CFrameWnd(LPCTSTR pszXMLPath, int uid);
  LPCTSTR GetWindowClassName() const override;
  CDuiString GetSkinFile()override;
  void InitWindow();
  void Notify(TNotifyUI &msg);
  static DWORD WINAPI test(LPVOID lp_param);
  LRESULT HandleCustomMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled)override;
  LRESULT OnUser(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled);
  void  refreshPro();
  void  KillPro();
  void  Inject(int type);
  void  EnumModule();
  BOOL MyWriteFile(const char* file, PVOID pdata, int writelen);
public:
  CDuiString                m_strXMLPath;
  HWND                      m_hParanWnd;
  CListUI*   m_plistuser;

public:
  void PostLog(const char *pData, ...);
  string GetDataDir(string name);
  void SetSkin(string xml);
  int IsNum(char s[]);

};
