
#include "FrameWnd.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include<stdio.h>
#include<algorithm>//因为用了sort()函数
#include<functional>//因为用了greater<int>()
#include "D:\\code\\glib\\glib\\glib\\gstring.h"
#include "D:\\code\\glib\\glib\\glib\\MemoryModule.h"
#include "D:\\code\\glib\\glib\\glib\\glog.h"
#include "D:\\code\\glib\\glib\\glib\\gprocess.h"
#include "D:\\code\\glib\\glib\\glib\\gManage.h"
#include "D:\\code\\glib\\glib\\glib\\gMd5.h"
#include "D:\\code\\Detours Pro v3.0.316\\include\\detours.h"
#include "D:\\code\\zlib\\zlib\\zlib.h"
#include "D:\\code\\zlib\\zlib\\zconf.h"
#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib,"D:\\code\\glib\\x64\\Debug\\glib.lib")
#else
#pragma comment(lib,"D:\\code\\glib\\Debug\\glib.lib")
#pragma comment(lib,"D:\\code\\zlib\\Debug\\zlib.lib")

#endif
#else
#ifdef _WIN64
#pragma comment(lib,"D:\\code\\glib\\x64\\Release\\glib.lib")
#pragma comment(lib,"D:\\code\\Detours Pro v3.0.316\\lib.X64\\detours.lib")
#pragma comment(lib,"D:\\code\\zlib\\x64\\Release\\zlib.lib")

#else
#pragma comment(lib,"D:\\code\\glib\\Release\\glib.lib")
#pragma comment(lib,"D:\\code\\Detours Pro v3.0.316\\lib.X86\\detours.lib")
#pragma comment(lib,"D:\\code\\zlib\\Release\\zlib.lib")
#endif
#endif
#include <comutil.h>

#include <atlbase.h>
#include <MsHTML.h>
#include <winternl.h>
#pragma comment(lib,"wininet.lib")


#include "detour64.h"
#include "detour32.h"









NTSTATUS ZwQueryVirtualMemory(
  _In_      HANDLE                   ProcessHandle,
  _In_opt_  PVOID                    BaseAddress,
  _In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
  _Out_     PVOID                    MemoryInformation,
  _In_      SIZE_T                   MemoryInformationLength,
  _Out_opt_ PSIZE_T                  ReturnLength
);
typedef struct _PROCESS_BASIC_INFORMATION64
{
  NTSTATUS ExitStatus;
  UINT32 Reserved0;
  UINT64 PebBaseAddress;
  UINT64 AffinityMask;
  UINT32 BasePriority;
  UINT32 Reserved1;
  UINT64 UniqueProcessId;
  UINT64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64;

typedef struct _PROCESS_BASIC_INFORMATION32
{
  NTSTATUS ExitStatus;
  UINT32 PebBaseAddress;
  UINT32 AffinityMask;
  UINT32 BasePriority;
  UINT32 UniqueProcessId;
  UINT32 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32;

#define NT_SUCCESS(x) ((x) >= 0)

#define ProcessBasicInformation 0
typedef
NTSTATUS(WINAPI *pfnNtWow64QueryInformationProcess64)
(HANDLE ProcessHandle, UINT32 ProcessInformationClass,
 PVOID ProcessInformation, UINT32 ProcessInformationLength,
 UINT32* ReturnLength);

typedef
NTSTATUS(WINAPI *pfnNtWow64ReadVirtualMemory64)
(HANDLE ProcessHandle, PVOID64 BaseAddress,
 PVOID BufferData, UINT64 BufferLength,
 PUINT64 ReturnLength);

typedef
NTSTATUS(WINAPI *pfnNtQueryInformationProcess)
(HANDLE ProcessHandle, ULONG ProcessInformationClass,
 PVOID ProcessInformation, UINT32 ProcessInformationLength,
 UINT32* ReturnLength);


CFrameWnd::CFrameWnd(LPCTSTR pszXMLPath)
{
  m_strXMLPath = pszXMLPath;
}

CFrameWnd::CFrameWnd(LPCTSTR pszXMLPath, int uid)
{
  m_strXMLPath = pszXMLPath;
  CListLabelElementUI *plb = new CListLabelElementUI();
}



LPCTSTR CFrameWnd::GetWindowClassName() const
{
  return _T("MainWnd");
}

CDuiString CFrameWnd::GetSkinFile()
{
  return m_strXMLPath;
}




void CFrameWnd::InitWindow()
{
  gProcess::EnableAllPrivilege(TRUE);
  gProcess::EnableDebugPrivilege();
  m_plistuser = static_cast<CListUI*>(m_PaintManager.FindControl(_T("socketlist")));
  refreshPro();
}


void CFrameWnd::Notify(TNotifyUI &msg)
{
  if(msg.sType == _T("menu"))
    {
    }

  if(msg.sType == _T("click"))
    {
      CDuiString name = msg.pSender->GetName();

      if(_stricmp(name.GetData(), "refresh") == 0)
        {
          this->refreshPro();
        }
      else if(_stricmp(name.GetData(), "kill") == 0)
        {
          this->KillPro();
        }
      else if(_stricmp(name.GetData(), "inject") == 0)
        {
          this->Inject(0);
        }
      else if(_stricmp(name.GetData(), "startinject") == 0)
        {
          this->Inject(1);
        }
      else if(_stricmp(name.GetData(), "getmodullist") == 0)
        {
          this->EnumModule();
        }
    }

  __super::Notify(msg);
}

LRESULT CFrameWnd::HandleCustomMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled)
{
  if(uMsg == WM_USER + 1)
    {
      OnUser(uMsg, wParam, lParam, bHandled);
      bHandled = false;
      return 0;
    }
  else if(uMsg == WM_USER + 2)
    {
      bHandled = false;
      return 0;
    }

_RET:
  bHandled = false;
  return 0;
}


LRESULT CFrameWnd::OnUser(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled)
{
  if(wParam == 2)
    {
    }

_ret:
//gstring::tip("%s",wParam);
  return 1;
}

std::string CFrameWnd::GetDataDir(string name)
{
  char pdir[216] = { 0 };
  GetModuleFileNameA(NULL, pdir, 216);
  PCHAR  pfind = strrchr((char *)pdir, '\\');

  if(pfind)
    {
      memset(pfind + 1, 0, 40);
      strcat(pdir, name.c_str());
    }

  return string(pdir);
}
int CFrameWnd::IsNum(char s[])
{
  int i = 0;

  for(i = 0; i < strlen(s); i++)
    {
      if(s[i] < '0' || s[i] > '9')
        {
          return 0;
        }
    }

  return 1;
}


void CFrameWnd::SetSkin(string xml)
{
  m_strXMLPath = CDuiString(xml.c_str());
}

void CFrameWnd::refreshPro()
{
  m_plistuser->RemoveAll();
  HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  if(hProcessSnap != INVALID_HANDLE_VALUE)
    {
      PROCESSENTRY32 pe32;
      pe32.dwSize = sizeof(pe32);
      BOOL bMore = ::Process32First(hProcessSnap, &pe32);

      while(bMore)
        {
          CListTextElementUI* pListElement = new CListTextElementUI;
          //m_plistuser->Add(pListElement);
          m_plistuser->AddAt(pListElement, 0);
          char vvv[20] = {0};
          int n = m_plistuser->GetCount();
          sprintf(vvv, "%d", n);
          pListElement->SetText(0, vvv);
          char pid[20] = {0};
          sprintf(pid, "%d(%x)", pe32.th32ProcessID, pe32.th32ProcessID);
          char parentid[20] = {0};
          sprintf(parentid, "%d(%x)", pe32.th32ParentProcessID, pe32.th32ParentProcessID);
          pListElement->SetText(1, pid);
          pListElement->SetText(2, pe32.szExeFile);
          pListElement->SetText(3, parentid);

          if(gstring::Is64BitPorcess(pe32.th32ProcessID))
            {
              pListElement->SetText(4, "64");
            }
          else
            {
              pListElement->SetText(4, "32");
            }

          //printf("进程名称:%s \n", pe32.szExeFile);
          //printf("进程ID号: %u \n\n", pe32.th32ProcessID);
          //pe32.th32ParentProcessID
          bMore = ::Process32Next(hProcessSnap, &pe32);
        }

      ::CloseHandle(hProcessSnap);
    }
}

void CFrameWnd::KillPro()
{
  int ncur = m_plistuser->GetCurSel();

  if(ncur == -1)
    {
      gstring::tip("请选择操作的进程");
      return;
    }

  CListTextElementUI* pText = (CListTextElementUI*) m_plistuser->GetItemAt(ncur);

  if(pText)
    {
      string strpid = pText->GetText(1);
      strpid = gstring::getStringContent(strpid.c_str(), "(", ")");
      DWORD dwPid = strtol(strpid.c_str(), NULL, 16);
      HANDLE hPro = OpenProcess(PROCESS_TERMINATE, FALSE, dwPid);

      if(hPro != INVALID_HANDLE_VALUE)
        {
          TerminateProcess(hPro, 0);
          this->refreshPro();
        }
    }
}

void CFrameWnd::Inject(int type)
{
  int ncur = m_plistuser->GetCurSel();

  if(ncur == -1)
    {
      gstring::tip("请选择操作的进程");
      return;
    }

  CListTextElementUI* pText = (CListTextElementUI*) m_plistuser->GetItemAt(ncur);

  if(pText)
    {
      string strpid = pText->GetText(1);
      strpid = gstring::getStringContent(strpid.c_str(), "(", ")");
      DWORD dwPid = strtol(strpid.c_str(), NULL, 16);
      string dllname = "";
      COptionUI*      m_pO1 = static_cast<COptionUI*>(m_PaintManager.FindControl(_T("o1")));

      if(m_pO1->IsSelected())
        {
          dllname = "dllpath32";
          //32 inject
        }
      else
        {
          dllname = "dllpath64";
        }

      CEditUI* pdllui = static_cast<CEditUI*>(m_PaintManager.FindControl(dllname.c_str()));

      if(pdllui)
        {
          string dllpath = pdllui->GetText();

          if(_access(dllpath.c_str(), 0) == 0)
            {
              if(type == 0)
                {
                  wstring wdllpath = gstring::s2w(dllpath);
                  BOOL bLoad =  gProcess::LoadDll(wdllpath.c_str(), dwPid);
                  //gstring::tip("%d", bLoad);
                }
              else
                {
                  char temp[1024] = {0};
                  GetTempPathA(1024, temp);

                  if(m_pO1->IsSelected())
                    {
                      strcat(temp, "detourDll32.dll");
                      MyWriteFile(temp, hexData, sizeof(hexData));
                    }
                  else
                    {
                      strcat(temp, "detourDll64.dll");
                      MyWriteFile(temp, hexData64, sizeof(hexData64));
                    }

                  CEditUI* pexepathui = static_cast<CEditUI*>(m_PaintManager.FindControl(_T("exepath")));
                  string exepath = pexepathui->GetText();
                  gstring::tip("begin inject");
                  STARTUPINFOA si = {0};
                  PROCESS_INFORMATION pi = {0};
                  DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED;
                  BOOL bdetour =  DetourCreateProcessWithDllExA(exepath.c_str(), (LPSTR)dllpath.c_str(), NULL, NULL, TRUE, dwFlags, NULL, NULL, &si, &pi, temp, NULL);

                  if(bdetour)
                    {
                      ResumeThread(pi.hThread);
                    }
                }
            }
          else
            {
              gstring::tip("请填写正确的dll路径");
            }
        }
    }
}

BOOL CFrameWnd::MyWriteFile(const char* file, PVOID pdata, int writelen)
{
  BOOL bret = FALSE;
  HANDLE hFile = ::CreateFileA(file, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if(hFile != INVALID_HANDLE_VALUE)
    {
      int towrite = 0;
      BOOL bwrite = WriteFile(hFile, pdata, writelen, (LPDWORD)&towrite, NULL);
      bret = bwrite;
      CloseHandle(hFile);
    }

  return bret;
}


typedef struct _PEB32   // Size: 0x1D8
{
  UCHAR InheritedAddressSpace;
  UCHAR ReadImageFileExecOptions;
  UCHAR BeingDebugged;
  UCHAR SpareBool;
  HANDLE Mutant;
  ULONG ImageBaseAddress;
  ULONG Ldr;
  ULONG ProcessParameters;    //进程参数块
} PEB32, *PPEB32;

typedef struct _PEB64   // Size: 0x1D8
{
  UCHAR InheritedAddressSpace;
  UCHAR ReadImageFileExecOptions;
  UCHAR BeingDebugged;
  UCHAR SpareBool[5];
  ULONG64 Mutant;
  ULONG64 ImageBaseAddress;
  ULONG64 Ldr;
  ULONG64 ProcessParameters;    //进程参数块
} PEB64, *PPEB64;



//typedef struct _PEB64
//{
//  UCHAR InheritedAddressSpace;
//  UCHAR ReadImageFileExecOptions;
//  UCHAR BeingDebugged;
//  UCHAR BitField;
//  ULONG64 Mutant;
//  ULONG64 ImageBaseAddress;
//  ULONG64 Ldr;
//  ULONG64 ProcessParameters;
//  ULONG64 SubSystemData;
//  ULONG64 ProcessHeap;
//  ULONG64 FastPebLock;
//  ULONG64 AtlThunkSListPtr;
//  ULONG64 IFEOKey;
//  ULONG64 CrossProcessFlags;
//  ULONG64 UserSharedInfoPtr;
//  ULONG SystemReserved;
//  ULONG AtlThunkSListPtr32;
//  ULONG64 ApiSetMap;
//} PEB64, *PPEB64;

typedef struct _PEB_LDR_DATA_
{
  DWORD Length;
  UCHAR Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
} PEB_LDR_DATA_, *PPEB_LDR_DATA_;




typedef struct _LDR_DATA_TABLE_ENTRY_
{
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  DWORD SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  DWORD Flags;
  WORD LoadCount;
  WORD TlsIndex;
  LIST_ENTRY HashLinks;
  PVOID SectionPointer;
  DWORD CheckSum;
  DWORD TimeDateStamp;
  PVOID LoadedImports;
  PVOID EntryPointActivationContext;
  PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY_, *PLDR_DATA_TABLE_ENTRY_;

typedef struct _UNICODE_STRING64
{
  USHORT Length;
  USHORT MaximumLength;
  ULONG64 Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
  LIST_ENTRY64 InLoadOrderLinks;
  LIST_ENTRY64 InMemoryOrderModuleList;
  LIST_ENTRY64 InInitializationOrderModuleList;
  ULONG64 DllBase;
  ULONG64 EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING64 FullDllName;
  UNICODE_STRING64 BaseDllName;
  ULONG Flags;
  USHORT LoadCount;
  USHORT TlsIndex;
  union
  {
    LIST_ENTRY64 HashLinks;
    ULONG64 SectionPointer;
  };
  ULONG CheckSum;
  union
  {
    ULONG TimeDateStamp;
    ULONG64 LoadedImports;
  };
  ULONG64 EntryPointActivationContext;
  ULONG64 PatchInformation;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

typedef struct _PEB_LDR_DATA64
{
  ULONG Length;
  BOOLEAN Initialized;
  ULONG64 SsHandle;
  LIST_ENTRY64 InLoadOrderModuleList;
  LIST_ENTRY64 InMemoryOrderModuleList;
  LIST_ENTRY64 InInitializationOrderModuleList;
  ULONG64 EntryInProgress;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;
void CFrameWnd::EnumModule()
{
  DWORD64 dwStartAddr = 0x00000000;
  ULONG    num = 0;
  BYTE szBuffer[MAX_PATH * 2 + 4] = {0};
  WCHAR szModuleName[MAX_PATH] = {0};
  WCHAR szPathName[MAX_PATH] = {0};
  MEMORY_BASIC_INFORMATION mbi;
  PUNICODE_STRING usSectionName;
  ZWQUERYVIRTUALMEMORY fnZwQueryVirtualMemory;
  BOOL modulex64 = FALSE;
  HANDLE hProcess = NULL;
  ULONG    dwRetVal = 0;
  int ncur = m_plistuser->GetCurSel();

  if(ncur == -1)
    {
      gstring::tip("请选择操作的进程");
      return;
    }

  CListTextElementUI* pText = (CListTextElementUI*) m_plistuser->GetItemAt(ncur);

  if(pText)
    {
      string strpid = pText->GetText(1);
      strpid = gstring::getStringContent(strpid.c_str(), "(", ")");
      DWORD dwProcessId = strtol(strpid.c_str(), NULL, 16);
      glog::trace("begin EnumModule dwProcessId:%d(%x)", dwProcessId, dwProcessId);
      string bit = pText->GetText(4);
      CListUI*   m_plistModule = static_cast<CListUI*>(m_PaintManager.FindControl(_T("modulelist")));
      m_plistModule->RemoveAll();

      if(bit == "32")
        {
          HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
          pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
          PROCESS_BASIC_INFORMATION32 pbi = { 0 };
          UINT32  ReturnLength = 0;
          HANDLE  m_ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);

          if(m_ProcessHandle == NULL)
            {
              glog::traceErrorInfo("OpenProcess", GetLastError());
              return;
            }

          PROCESS_BASIC_INFORMATION32 pbi32 = { 0 };

          if(NT_SUCCESS(NtQueryInformationProcess(m_ProcessHandle, ProcessBasicInformation, &pbi32, sizeof(pbi32), NULL)))
            {
              DWORD Ldr32 = 0;
              LIST_ENTRY ListEntry32 = { 0 };
              LDR_DATA_TABLE_ENTRY_ LDTE32 = { 0 };
              wchar_t ProPath32[256];
              wchar_t ProName32[256];

              if(ReadProcessMemory(m_ProcessHandle, (PVOID)(pbi32.PebBaseAddress + offsetof(PEB32, Ldr)), &Ldr32, sizeof(Ldr32), NULL))
                {
                  if(ReadProcessMemory(m_ProcessHandle, (PVOID)(Ldr32 + offsetof(PEB_LDR_DATA_, InLoadOrderModuleList)), &ListEntry32, sizeof(LIST_ENTRY32), NULL))
                    {
                      if(ReadProcessMemory(m_ProcessHandle, (PVOID)(ListEntry32.Flink), &LDTE32, sizeof(LDR_DATA_TABLE_ENTRY), NULL))
                        {
                          while(1)
                            {
                              if(LDTE32.InLoadOrderLinks.Flink == ListEntry32.Flink) break;

                              ReadProcessMemory(m_ProcessHandle, (PVOID)LDTE32.FullDllName.Buffer, ProPath32, sizeof(ProPath32), NULL);
                              ReadProcessMemory(m_ProcessHandle, (PVOID)LDTE32.BaseDllName.Buffer, ProName32, sizeof(ProName32), NULL);
                              PVOID base = LDTE32.DllBase;
                              ULONG msize = LDTE32.SizeOfImage;
                              string mname = gstring::w2s(ProName32);
                              string mfullname = gstring::w2s(ProPath32);
                              char pbase[30] = {0};
                              char psize[30] = {0};
                              sprintf(pbase, "%x", base);
                              sprintf(psize, "%x", msize);
                              CListTextElementUI* pListElement = new CListTextElementUI;
                              m_plistModule->Add(pListElement);
                              pListElement->SetText(0, mname.c_str());
                              pListElement->SetText(1, pbase);
                              pListElement->SetText(2, psize);
                              pListElement->SetText(3, mfullname.c_str());

                              if(!ReadProcessMemory(m_ProcessHandle, (PVOID)LDTE32.InLoadOrderLinks.Flink, &LDTE32, sizeof(LDR_DATA_TABLE_ENTRY_), NULL)) break;
                            }
                        }
                    }
                }
            }

          CloseHandle(m_ProcessHandle);
        }
      else
        {
          HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
          pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
          pfnNtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = (pfnNtWow64ReadVirtualMemory64)GetProcAddress(NtdllModule, "NtWow64ReadVirtualMemory64");
          PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };
          HANDLE  m_ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);

          if(m_ProcessHandle == NULL)
            {
              glog::traceErrorInfo("OpenProcess", GetLastError());
              return;
            }

          if(NT_SUCCESS(NtWow64QueryInformationProcess64(m_ProcessHandle, ProcessBasicInformation, &pbi64, sizeof(pbi64), NULL)))
            {
              DWORD64 Ldr64 = 0;
              LIST_ENTRY64 ListEntry64 = { 0 };
              LDR_DATA_TABLE_ENTRY64 LDTE64 = { 0 };
              wchar_t ProPath64[256] = {0};
              wchar_t ProName64[256] = {0};

              if(NT_SUCCESS(NtWow64ReadVirtualMemory64(m_ProcessHandle, (PVOID64)(pbi64.PebBaseAddress + offsetof(PEB64, Ldr)), &Ldr64, sizeof(Ldr64), NULL)))
                {
                  if(NT_SUCCESS(NtWow64ReadVirtualMemory64(m_ProcessHandle, (PVOID64)(Ldr64 + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList)), &ListEntry64, sizeof(LIST_ENTRY64), NULL)))
                    {
                      if(NT_SUCCESS(NtWow64ReadVirtualMemory64(m_ProcessHandle, (PVOID64)(ListEntry64.Flink), &LDTE64, sizeof(_LDR_DATA_TABLE_ENTRY64), NULL)))
                        {
                          while(1)
                            {
                              if(LDTE64.InLoadOrderLinks.Flink == ListEntry64.Flink) break;

                              NtWow64ReadVirtualMemory64(m_ProcessHandle, (PVOID64)LDTE64.FullDllName.Buffer, ProPath64, sizeof(ProPath64), NULL);
                              NtWow64ReadVirtualMemory64(m_ProcessHandle, (PVOID64)LDTE64.BaseDllName.Buffer, ProName64, sizeof(ProPath64), NULL);
                              ULONG64 base = LDTE64.DllBase;
                              ULONG msize = LDTE64.SizeOfImage;
                              string mname = gstring::w2s(ProName64);
                              string mfullname = gstring::w2s(ProPath64);
                              char pbase[30] = {0};
                              char psize[30] = {0};
                              sprintf(pbase, "%llx", base);
                              sprintf(psize, "%x", msize);
                              CListTextElementUI* pListElement = new CListTextElementUI;
                              m_plistModule->Add(pListElement);
                              pListElement->SetText(0, mname.c_str());
                              pListElement->SetText(1, pbase);
                              pListElement->SetText(2, psize);
                              pListElement->SetText(3, mfullname.c_str());

                              if(!NT_SUCCESS(NtWow64ReadVirtualMemory64(m_ProcessHandle, (PVOID64)LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(_LDR_DATA_TABLE_ENTRY64), NULL))) break;
                            }
                        }
                    }
                }
            }

          CloseHandle(m_ProcessHandle);
          //HMODULE NtdllModule = GetModuleHandleW(L"ntdll.dll");
          //pfnNtWow64QueryInformationProcess64 NtWow64QueryInformationProcess64 = (pfnNtWow64QueryInformationProcess64)GetProcAddress(NtdllModule, "NtWow64QueryInformationProcess64");
          //pfnNtWow64ReadVirtualMemory64 NtWow64ReadVirtualMemory64 = (pfnNtWow64ReadVirtualMemory64)GetProcAddress(NtdllModule, "NtWow64ReadVirtualMemory64");
          //PROCESS_BASIC_INFORMATION64 pbi = { 0 };
          //UINT64 ReturnLength = 0;
          //hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);
          //if(hProcess == NULL)
          //  {
          //    glog::traceErrorInfo("OpenProcess", GetLastError());
          //    return;
          //  }
          //NTSTATUS Status = NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &pbi,sizeof(PROCESS_BASIC_INFORMATION64), (UINT32*)&ReturnLength);
          //if(NT_SUCCESS(Status))
          //  {
          //    PEB64 peb64 = {0};
          //    Status =   NtWow64ReadVirtualMemory64(hProcess, (PVOID)pbi.PebBaseAddress, (PEB64*)&peb64, sizeof(PEB64), NULL);
          //    if(NT_SUCCESS(Status))
          //      {
          //        PEB_LDR_DATA_   ldr = {0};
          //        Status =   NtWow64ReadVirtualMemory64(hProcess, (PVOID)peb64.DllList, (PEB_LDR_DATA_*)&ldr, sizeof(PEB_LDR_DATA_), NULL);
          //        if(NT_SUCCESS(Status))
          //          {
          //            LDR_DATA_TABLE_ENTRY_ entry = {0};
          //            Status =   NtWow64ReadVirtualMemory64(hProcess, (PVOID)ldr.InLoadOrderModuleList.Flink, (LDR_DATA_TABLE_ENTRY_*)&entry, sizeof(LDR_DATA_TABLE_ENTRY_), NULL);
          //            if(NT_SUCCESS(Status))
          //              {
          //                LDR_DATA_TABLE_ENTRY_ EndEntry = {0};
          //                Status =   NtWow64ReadVirtualMemory64(hProcess, (PVOID)entry.InLoadOrderLinks.Flink, (LDR_DATA_TABLE_ENTRY_*)&EndEntry, sizeof(LDR_DATA_TABLE_ENTRY_), NULL);
          //                glog::trace("base:%p size:%x\n", entry.DllBase, entry.SizeOfImage);
          //                CListUI*   m_plistModule = static_cast<CListUI*>(m_PaintManager.FindControl(_T("modulelist")));
          //                int  ncount = 0;
          //                if(m_plistModule)
          //                  {
          //                    m_plistModule->RemoveAll();
          //                    while(NT_SUCCESS(Status) && entry.InLoadOrderLinks.Flink != EndEntry.InLoadOrderLinks.Flink)
          //                      {
          //                        if(ncount == 0)
          //                          {
          //                            WCHAR baseName[216] = {0};
          //                            WCHAR FullPath[216] = {0};
          //                            PVOID base = entry.DllBase;
          //                            ULONG msize = entry.SizeOfImage;
          //                            ReadProcessMemory(hProcess, (PVOID)entry.BaseDllName.Buffer, baseName, entry.BaseDllName.Length, NULL);
          //                            ReadProcessMemory(hProcess, (PVOID)entry.FullDllName.Buffer, FullPath, entry.FullDllName.Length, NULL);
          //                            string mname = gstring::w2s(baseName);
          //                            string mfullname = gstring::w2s(FullPath);
          //                            char pbase[20] = {0};
          //                            char psize[20] = {0};
          //                            sprintf(pbase, "%p", base);
          //                            sprintf(psize, "%x", msize);
          //                            CListTextElementUI* pListElement = new CListTextElementUI;
          //                            m_plistModule->Add(pListElement);
          //                            pListElement->SetText(0, mname.c_str());
          //                            pListElement->SetText(1, pbase);
          //                            pListElement->SetText(2, psize);
          //                            pListElement->SetText(3, mfullname.c_str());
          //                          }
          //                        else
          //                          {
          //                            WCHAR baseName[216] = {0};
          //                            WCHAR FullPath[216] = {0};
          //                            PVOID base = EndEntry.DllBase;
          //                            ULONG msize = EndEntry.SizeOfImage;
          //                            ReadProcessMemory(hProcess, (PVOID)EndEntry.BaseDllName.Buffer, baseName, EndEntry.BaseDllName.Length, NULL);
          //                            ReadProcessMemory(hProcess, (PVOID)EndEntry.FullDllName.Buffer, FullPath, EndEntry.FullDllName.Length, NULL);
          //                            string mname = gstring::w2s(baseName);
          //                            string mfullname = gstring::w2s(FullPath);
          //                            char pbase[20] = {0};
          //                            char psize[20] = {0};
          //                            sprintf(pbase, "%p", base);
          //                            sprintf(psize, "%x", msize);
          //                            CListTextElementUI* pListElement = new CListTextElementUI;
          //                            m_plistModule->Add(pListElement);
          //                            pListElement->SetText(0, mname.c_str());
          //                            pListElement->SetText(1, pbase);
          //                            pListElement->SetText(2, psize);
          //                            pListElement->SetText(3, mfullname.c_str());
          //                            glog::trace("base:%p size:%x\n", EndEntry.DllBase, EndEntry.SizeOfImage);
          //                          }
          //                        ncount += 1;
          //                        Status =   NtWow64ReadVirtualMemory64(hProcess, (PVOID)EndEntry.InLoadOrderLinks.Flink, (LDR_DATA_TABLE_ENTRY_*)&EndEntry, sizeof(LDR_DATA_TABLE_ENTRY_), NULL);
          //                      }
          //                  }
          //              }
          //          }
          //      }
          //  }
          //CloseHandle(hProcess);
        }

      //hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);
      //if(hProcess == NULL)
      //  {
      //    glog::traceErrorInfo("OpenProcess", GetLastError());
      //    return;
      //  }
      //dwStartAddr = 0x0000000000000000;
      //fnZwQueryVirtualMemory = (ZWQUERYVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryVirtualMemory");
      //if(fnZwQueryVirtualMemory)
      //  {
      //    do
      //      {
      //        if(fnZwQueryVirtualMemory(hProcess, (PVOID64)dwStartAddr, MemoryBasicInformation, &mbi, sizeof(mbi), 0) >= 0)
      //          {
      //            if(mbi.Type == MEM_IMAGE)
      //              {
      //                if(fnZwQueryVirtualMemory(hProcess, (PVOID64)dwStartAddr, MemorySectionName, szBuffer, sizeof(szBuffer), 0) >= 0)
      //                  {
      //                    usSectionName = (PUNICODE_STRING)szBuffer;
      //                    glog::trace("usSectionName:%wZ", usSectionName);
      //                    //if(_wcsnicmp(szModuleName, usSectionName->Buffer, usSectionName->Length / sizeof(WCHAR)))
      //                    //  {
      //                    //    wcsncpy(szModuleName, usSectionName->Buffer, usSectionName->Length / sizeof(WCHAR));
      //                    //    szModuleName[usSectionName->Length / sizeof(WCHAR)] = UNICODE_NULL;
      //                    //    // DeviceName2PathName(szPathName, szModuleName);
      //                    //    wprintf(L"[0x%.8llx]\t%s\n", dwStartAddr, szPathName);
      //                    //
      //                    //  }
      //                    num++;
      //                  }
      //              }
      //          }
      //        // 递增基址,开始下一轮查询!
      //        dwStartAddr += (ULONGLONG)0x4000;
      //        if(!modulex64)
      //          {
      //            if(dwStartAddr > 0x0000000200000000)
      //              {
      //                modulex64 = TRUE;
      //                dwStartAddr = 0x000007fe00000000;
      //              }
      //          }
      //      }
      //    while(dwStartAddr < 0x000007ff00000000);
      //  }
      //CloseHandle(hProcess);
    }
}


