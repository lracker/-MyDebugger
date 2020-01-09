// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

extern "C" __declspec(dllexport) void Init(char* name);
extern "C" __declspec(dllexport) void Run(HANDLE hProcess, const char* DllPath);


void Init(char* name)
{
	strcpy_s(name, 32, "AntiDebug.dll");
}

void Run(HANDLE hProcess, const char* DllPath)
{
	// 在目标进程中申请空间
	LPVOID lpPathAddr = VirtualAllocEx(hProcess, 0, strlen(DllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	// 在目标进程空间中写入dll的路径
	DWORD dwWriteSize = 0;
	WriteProcessMemory(hProcess, lpPathAddr, DllPath, strlen(DllPath) + 1, &dwWriteSize);
	// 在目标进程中创建线程
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (PTHREAD_START_ROUTINE)LoadLibraryA, lpPathAddr, NULL, NULL);
	CloseHandle(hThread);
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

