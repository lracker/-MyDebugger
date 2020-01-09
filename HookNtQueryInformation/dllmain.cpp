// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <winternl.h>
#include <string>
using std::string;
BYTE g_NewCode[5] = { 0xE9 };
BYTE g_OldCode[5] = {};
int g_nId = 0;
void OnHook();
void UnHook();
void AntiBeingDebugged();

//******************************************************************************
// 函数名称: AntiBeingDebugger
// 函数说明: 修改BeingDebugged
// 作    者: lracker
// 时    间: 2019/10/29
// 返 回 值: void
//******************************************************************************
void AntiBeingDebugged()
{
	__asm {
		mov eax, dword ptr FS : [0x30] 
		mov byte ptr[eax + 0x2], 0
	}
}
__kernel_entry NTSTATUS
NTAPI
MyNtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
)
{
	NTSTATUS status = TRUE;
	UnHook();
	switch (ProcessInformationClass)
	{
	case ProcessDebugPort:
		ProcessInformation = NULL;
		break;
	case 0x1e:
		*(char*)ProcessInformation = NULL;
		break;
	case 0x1F:
		*(int*)ProcessInformation = 0;
		break;
	default:
		break;
	}
	OnHook();
//	UnHook();
	return status;
}
void OnHook()
{
	//MessageBox(0, 0, 0, 0);
	HMODULE hModule = LoadLibraryA("Ntdll.dll");
	LPVOID Func = GetProcAddress(hModule, "NtQueryInformationProcess");
	// 保存原函数地址
	memcpy(g_OldCode, Func, 5);
	DWORD dwOffset = (DWORD)MyNtQueryInformationProcess - (DWORD)Func - 5;
	memcpy(&g_NewCode[1], &dwOffset, 4);
	DWORD dwOldProtect;
	VirtualProtect(Func, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(Func, g_NewCode, 5);
	VirtualProtect(Func, 5, dwOldProtect, &dwOldProtect);
}
void UnHook() 
{
	HMODULE hModule = LoadLibraryA("Ntdll.dll");
	LPVOID Func = GetProcAddress(hModule, "NtQueryInformationProcess");
	DWORD dwOldProtect;
	VirtualProtect(Func, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(Func, g_OldCode, 5);
	VirtualProtect(Func, 5, dwOldProtect, &dwOldProtect);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		AntiBeingDebugged();
		OnHook();
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

