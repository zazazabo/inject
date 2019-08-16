// dnf.cpp : Defines the entry point for the DLL application.
//

#include "template.h"  //改成的头文件名
#include "resource.h"
#include "FrameWnd.h"
#include <commctrl.h>

#include <atlconv.h>
#include "D:\\code\\glib\\glib\\glib\\gstring.h"
#include "D:\\code\\glib\\glib\\glib\\MemoryModule.h"
#include "D:\\code\\glib\\glib\\glib\\glog.h"
#include "D:\\code\\glib\\glib\\glib\\gprocess.h"
#include "D:\\code\\zlib\\zlib\\zlib.h"
#include "D:\\code\\zlib\\zlib\\zconf.h"
#include "D:\\code\\Detours Pro v3.0.316\\include\\detours.h"
#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib,"D:\\code\\glib\\x64\\Debug\\glib.lib")
#else
#pragma comment(lib,"D:\\code\\glib\\Debug\\glib.lib")
#pragma comment(lib,"D:\\code\\Detours Pro v3.0.316\\lib.X86\\detours.lib")

#endif
#else
#ifdef _WIN64
#pragma comment(lib,"D:\\code\\glib\\x64\\Release\\glib.lib")
#pragma comment(lib,"D:\\code\\zlib\\x64\\Release\\zlib.lib")

#else
#pragma comment(lib,"D:\\code\\glib\\Release\\glib.lib")
#pragma comment(lib,"D:\\code\\zlib\\Release\\zlib.lib")
#pragma comment(lib,"D:\\code\\Detours Pro v3.0.316\\lib.X86\\detours.lib")
#endif
#endif
#pragma comment(lib,"comctl32.lib")

HWND  hWindow;
HINSTANCE hInst;



int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
  gstring::setIcon(NULL, IDI_ICON1);
  glog::setOpenLog(TRUE);
  hInst = hInstance;

  
  LPVOID a1 = NULL;
  int    size1 = 0;
  CPaintManagerUI::SetInstance(hInstance);
#ifdef _DEBUG
  CPaintManagerUI::SetResourcePath("skin");
#else
  gstring::getResInfo(a1, size1, IDR_ZIP1, "zip", hInstance);
  CPaintManagerUI::SetResourceZip(a1, size1);
#endif
  CFrameWnd *pFrame = new CFrameWnd("");
  pFrame->SetSkin("test1.xml");
  pFrame->Create(NULL, _T("duilib窗口"), UI_WNDSTYLE_CONTAINER, UI_WNDSTYLE_EX_DIALOG);
  SetForegroundWindow(pFrame->GetHWND());
  pFrame->ShowModal();
  delete pFrame;
  ::CoUninitialize();
  return 0;
  return TRUE;
  return TRUE;
}





