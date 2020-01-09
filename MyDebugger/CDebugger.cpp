#include <iostream>
#include "CDebugger.h"
#include "CCapstone.h"
#include "CBreakPoint.h"
#include "dbgHelp.h"
#include <TlHelp32.h>
#include <atlconv.h>
#include <tchar.h>
#include "keystone/include/keystone.h"
#pragma comment(lib, "dbghelp.lib")
#pragma comment (lib,"keystone/lib/keystone_x86.lib")

#define DLLPATH "C:\\Users\\Canary\\Desktop\\15PB\\第二阶段\\MyDebugger\\HookNtQueryInformation.dll"
LPVOID FileBuff = nullptr;
BOOL First = TRUE;
BOOL Initiative = FALSE;
BOOL ReadWrite = FALSE;
HANDLE g_hProcess = NULL;
using PFUNC1 = void(*)(char*);
using PFUNC2 = void(*)(HANDLE hProcess, const char* DllPath);
//******************************************************************************
// 函数名称: Open
// 函数说明: 接收一个路径，以调试的方式创建进程
// 作    者: lracker
// 时    间: 2019/10/25
// 参    数: LPCSTR FilePath
// 返 回 值: void
//******************************************************************************
void CDebugger::Open(LPCSTR FilePath)
{
	// 如果进程创建成功，用于接收进程线程的句柄和ID
	PROCESS_INFORMATION ProcessInfo = { 0 };
	STARTUPINFOA StartupInfo = { sizeof(STARTUPINFO) };
	// 以调试方式创建进程
	BOOL result = CreateProcessA(FilePath, nullptr, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInfo);
	if (result == TRUE)
	{
		// 遍历插件,使用插件反调试了
		for (auto& i : PluginsVector)
		{
			// 找到插件MyNtQueryInformationProcess.dll
			if (!strcmp(i.name, "AntiDebug.dll"))
			{
				// 调用插件的Run函数
				PFUNC2 Func = (PFUNC2)GetProcAddress(i.Base, "Run");
				if (Func)
				{
					Func(ProcessInfo.hProcess, DLLPATH);
					break;
				}
			}
		}
		g_hProcess = ProcessInfo.hProcess;
		// 加载调试符号
		CloseHandle(ProcessInfo.hThread);
	//	CloseHandle(ProcessInfo.hProcess);
	}
	// 初始化反汇编引擎
	CCapstone::Init();
}

//******************************************************************************
// 函数名称: Run
// 函数说明: 接收并处理调试事件
// 作    者: lracker
// 时    间: 2019/10/25
// 返 回 值: void
//******************************************************************************
void CDebugger::Run()
{
	BOOL First = TRUE;
	// 通过循环不断的从调试对象中获取到调试信息
	while (WaitForDebugEvent(&DebugEvent, INFINITE))
	{
		OpenHandles();
		switch (DebugEvent.dwDebugEventCode)
		{
			// 异常调试事件
		case EXCEPTION_DEBUG_EVENT:
			OnExceptionEvent();
			break;
			// 进程创建事件
		case CREATE_PROCESS_DEBUG_EVENT:
		{
			// 获取OEP函数
			LPVOID OEPEntry = DebugEvent.u.CreateProcessInfo.lpStartAddress;
			// 然后设置一个CC断点，一次性的，一会儿自动删掉的
			CBreakPoint::SetCCBreakPoint(ProcessHandle, OEPEntry, TRUE);
			break;
		}
		}
		CloseHandles();
		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, dwCountinueStatus);
	}
}

//******************************************************************************
// 函数名称: InitPlugin
// 函数说明: 加载插件的
// 作    者: lracker
// 时    间: 2019/10/29
// 返 回 值: void
//******************************************************************************
void CDebugger::InitPlugin()
{
	string PluginPath = "plugin/";
	string PFindPluginPath = "plugin/*.dll";
	// 保存遍历到的文件信息
	WIN32_FIND_DATAA FileInfo = { 0 };
	// 遍历插件的路径，可以设置后缀名
	HANDLE FindHandle = FindFirstFileA(PFindPluginPath.c_str(), &FileInfo);
	// 一个一个遍历
	do {
		string FilePath = PluginPath + FileInfo.cFileName;
		// 加载DLL文件，并且保存到一个容器
		HMODULE Handle = LoadLibraryA(FilePath.c_str());
		// 如果模块加载成功，需要插件提供自己的信息，形式是导出一个特定的函数
		if (Handle)
		{
			PLGINFO info = { Handle };
			PFUNC1 func = (PFUNC1)GetProcAddress(Handle, "Init");
			// 如果函数获取成功
			if (func)
			{
				func(info.name);
				PluginsVector.push_back(info);
				printf("插件%s已经加载了\n", info.name);
			}
		}
	} while (FindNextFileA(FindHandle, &FileInfo));
	FindClose(FindHandle);


}


//******************************************************************************
// 函数名称: OpenHandles
// 函数说明: 提供函数用于打开目标进程句柄
// 作    者: lracker
// 时    间: 2019/10/25
// 返 回 值: void
//******************************************************************************
void CDebugger::OpenHandles()
{
	ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
}

//******************************************************************************
// 函数名称: CloseHandles
// 函数说明:提供函数用于关闭句柄
// 作    者: lracker
// 时    间: 2019/10/25
// 返 回 值: void
//******************************************************************************
void CDebugger::CloseHandles()
{
	CloseHandle(ThreadHandle);
	CloseHandle(ProcessHandle);
}

//******************************************************************************
// 函数名称: OnExceptionEvent
// 函数说明: 用于处理接收到的所有异常事件
// 作    者: lracker
// 时    间: 2019/10/25
// 返 回 值: void
//******************************************************************************
void CDebugger::OnExceptionEvent()
{
	// 获取异常产生的地址以及异常的类型
	DWORD dwCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID Addr = DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	// 输出异常的信息和产生的位置
	// 如果是我们g主动发出的单步异常的话，就不显示了
	if(!Initiative)
		printf("Type(%08X): %p\n", dwCode, Addr);
	switch (dwCode)
	{
		// 设备访问异常：和内存断点相关
	case EXCEPTION_ACCESS_VIOLATION:
	{

		DWORD64 MemAddrStart = m_MemAddr & 0xFFFFF000;
		// 改变页面属性
		VirtualProtectEx(ProcessHandle, (LPVOID)MemAddrStart, 0x1000, m_dwOldProtect, &m_dwOldProtect);
		CBreakPoint::MemChange = TRUE;
		Initiative = TRUE;
		// 判断是否在那一页内
		if ((DWORD64)Addr >= MemAddrStart && (DWORD64)Addr <= (MemAddrStart + 0x1000))
		{
			// 内存执行断点
			CBreakPoint::SetTFBreakPoint(ThreadHandle);
			ReadWrite = FALSE;
			return;
		}
		else
		{
			// 内存访问断点
			CBreakPoint::SetCCBreakPoint(ProcessHandle, Addr, TRUE);
			ReadWrite = TRUE;
			return;
		}
		break;
	}
	// 断点异常: int 3(0xCC)会触发的异常
	case EXCEPTION_BREAKPOINT:
	{
		// 当进程被创建的时候，操作系统会检测当前的
		// 进程是否处于被调试状态，如果被调试了，就
		// 会通过 int 3 设置一个软件断点，这个断点
		// 通常不需要处理
		if (First)
		{
			Addr = (char*)Addr + 1;
			First = FALSE;
		}
		// 接下来就是我们设置的 int 3断点，需要进行处理
		else
		{			
			CBreakPoint::FixCCBreakPoint(ProcessHandle, ThreadHandle, Addr);
			// 首先判断一下断点的条件是否成立 
			// 如果成立的话，则断下来。
			// 否则不断下来。
			if (!CBreakPoint::IsCondition(ThreadHandle, Addr))
			{
				if (CBreakPoint::CCChange)
				{
					Initiative = TRUE;
					CBreakPoint::SetTFBreakPoint(ThreadHandle);
				}
				return;
			}
		}
		break;
	}
	// 硬件断点事件: TF单步， DrN断点
	case EXCEPTION_SINGLE_STEP:
	{	// 获取线程环境块，调试用
		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(ThreadHandle, &ct);
		// 如果是内存断点改变了状态
		if (CBreakPoint::MemChange)
		{
			DWORD64 MemAddrStart = m_MemAddr & 0xFFFFF000;
			VirtualProtectEx(ProcessHandle, (LPVOID)MemAddrStart, 0x1000, m_dwOldProtect, &m_dwOldProtect);
			CBreakPoint::MemChange = FALSE;
			if (Initiative)
			{
				Initiative = FALSE;
			}
			// 如果是内存访问断点的话
			if (ReadWrite)
			{
				return;
			}
		}
		if (CBreakPoint::CCChange)
		{
			// 重新遍历一下CC断点列表
			CBreakPoint::ResetCCBreakPoint(ProcessHandle);
			if (Initiative)
			{
				Initiative = FALSE;
				return;
			}
		}
		// 如果硬件断点之前改变了状态了
		if (CBreakPoint::HWChange)
		{
			// 重新设置上一个硬件断点为开的
			CBreakPoint::ResetHWBreakPoint(ThreadHandle);
			if (Initiative)
			{
				Initiative = FALSE;
				return;
			}
		}
		else
		{
			// 假如是硬件断点的话，则要取
			CBreakPoint::FixHWBreakPoint(ThreadHandle);
		}
		break;
	}
	}
	// 查看反汇编前需要把所有的断点恢复成原来的opcode
	CBreakPoint::RecoverOpcode(ProcessHandle);
	// 应该查看的是 eip 指向的位置，而不是异常的位置
	CCapstone::DisAsm(ProcessHandle, (LPVOID)((char*)Addr), 10);
	// 看完反汇编后需要把所有的断点恢复成CC
	CBreakPoint::RecoverCC(ProcessHandle, ThreadHandle, (LPVOID)Addr);
	// 获取用户的输入了
	GetCommend();
}

//******************************************************************************
// 函数名称: getCommend
// 函数说明: 获取用户的输入
// 作    者: lracker
// 时    间: 2019/10/25
// 返 回 值: void
//******************************************************************************
void CDebugger::GetCommend()
{
	char input[0x100] = { 0 };
	while (TRUE)
	{
		printf(">>");
		// 获取指令，指令应该是事先考虑好的了
		scanf_s("%s", input, 0x100);
		// 根据输入的指令执行不同的操作
		// 直接跑起来
		if (!strcmp(input, "g"))
		{
			// 结束输入，让程序继续执行，直到运行
			// 结束或者遇到下一个异常
			// 如果CC断点修复过了，则主动发送一个异常，重新设置CC断点
			if (CBreakPoint::CCChange || CBreakPoint::HWChange || CBreakPoint::MemChange)
			{
				Initiative = TRUE;
				CBreakPoint::SetTFBreakPoint(ThreadHandle);
			}
			break;
		}
		// 查看反汇编，格式：u 地址 条数
		else if (!strcmp(input, "u"))
		{
			int addr = 0, lines = 0;
			scanf_s("%x %d", &addr, &lines);
			// 查看反汇编前需要把所有的断点恢复成原来的opcode
			CBreakPoint::RecoverOpcode(ProcessHandle);
			CCapstone::DisAsm(ProcessHandle, (LPVOID)addr, lines);
			// 看完反汇编后需要把所有的断点恢复成CC
			CBreakPoint::RecoverCC(ProcessHandle, ThreadHandle, (LPVOID)addr);
		}
		// 查看寄存器
		else if (!strcmp(input, "r"))
		{
			// 先清空容器
			MyRegisterVector.clear();
			// 获取寄存器的信息到容器里，并且打印出来
			GetRegister(ThreadHandle, MyRegisterVector);
			for (auto& i : MyRegisterVector)
			{
				printf("%s", i.c_str());
			}
			printf("\n");
		}
		// 查看栈信息
		else if (!strcmp(input, "k"))
		{
			// 获取栈信息到容器里
			MyStackVector.clear();
			GetStack(ProcessHandle, ThreadHandle, MyStackVector);
			for (auto& i : MyStackVector)
			{
				printf("%s\n", i.c_str());
			}
		}
		// 查看内存数据,格式：m 地址
		else if (!strcmp(input, "m"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			// 设置内存页
			GetMemory(ProcessHandle, (LPVOID)addr);
			printf("\n");
		}
		// 查看模块信息
		else if (!strcmp(input, "lm"))
		{
			MyModuleVector.clear();
			GetModules();
			printf("序号    ");
			printf("start    ");
			printf("end      ");
			printf("ModuleName\n");
			int j = 0;
			for (auto& i : MyModuleVector)
			{
				printf("%d\t", ++j);
				printf("%08x ", i.ModuleStartAddr);
				printf("%08x ", i.ModuleEndAddr);
				printf("%s\n", i.ModuleName.c_str());
			}
		}
		// 查看模块的输入输出表
		else if (!strcmp(input, "mt"))
		{
			printf("请输入你要查看的模块的序号\n");
			int i = 0;
			scanf_s("%d", &i);
			GetTable(i - 1);
		}
		// 查看所有的CC断点
		else if (!strcmp(input, "dbp"))
		{
			printf("CC断点如下:\n");
			for (int i = 0; i < CBreakPoint::BreakPointList.size(); i++)
			{
				printf("第%d个断点: %p\n", i + 1, CBreakPoint::BreakPointList[i].addr);
			}
		}
		// 下一个软件断点0xCC
		else if (!strcmp(input, "bp"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			CBreakPoint::SetCCBreakPoint(ProcessHandle, (LPVOID)addr, FALSE);
		}
		// 下一个条件断点0xCC
		else if (!strcmp(input, "bd"))
		{
			int Addr = 0;
			char Reg[10] = {};
			char Operator[5] = {};
			int nValue = 0;
			scanf_s("%x", &Addr);
			scanf_s("%s%s%x", Reg, 10, Operator, 5, &nValue);
			CBreakPoint::ConditionCCBreakPoint(ProcessHandle, (LPVOID)Addr, Reg, Operator, nValue);
		}
		// 下一个硬件执行断点
		else if (!strcmp(input, "hxbp"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			CBreakPoint::SetHWBreakPoint(ThreadHandle, (LPVOID)addr, 0, 0);
		}
		// 下一个硬件写入断点 多少个字节
		// 格式 hwbp Addr nLen
		else if (!strcmp(input, "hwbp"))
		{
			int addr = 0, nLen = 0;
			scanf_s("%x %d", &addr, &nLen);
			CBreakPoint::SetHWBreakPoint(ThreadHandle, (LPVOID)addr, 1, nLen);
		}
		// 下一个硬件访问(读写)断点 多少个字节
		// 格式 hrwbp Addr nLen
		else if (!strcmp(input, "hrwbp"))
		{
			int addr = 0, nLen = 0;
			scanf_s("%x %d", &addr, &nLen);
			CBreakPoint::SetHWBreakPoint(ThreadHandle, (LPVOID)addr, 3, nLen);
		}
		// 下一个内存访问(读写)断点
		else if (!strcmp(input, "mrwbp"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			CBreakPoint::SetMemBreakPoint(ProcessHandle, (LPVOID)addr, m_MemAddr, m_dwOldProtect, PAGE_NOACCESS);
		}
		// 下一个内存写入断点
		else if (!strcmp(input, "mwbp"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			CBreakPoint::SetMemBreakPoint(ProcessHandle, (LPVOID)addr, m_MemAddr, m_dwOldProtect, PAGE_READONLY);
		}
		// 下一个内存执行断点
		else if (!strcmp(input, "mxbp"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			CBreakPoint::SetMemBreakPoint(ProcessHandle, (LPVOID)addr, m_MemAddr, m_dwOldProtect, PAGE_READWRITE);
		}
		// 单步步入，tf断点
		else if (!strcmp(input, "t"))
		{
			// 告诉单步异常那里，代表了这是一个单步异常所导致的
			CBreakPoint::SetTFBreakPoint(ThreadHandle);
			break;
		}
		// 单步步过
		else if (!strcmp(input, "p"))
		{
			// 设置单步步过
			CBreakPoint::SetStepBreakPoint(ProcessHandle, ThreadHandle);
			break;
		}
		// 修改内存的值
		else if (!strcmp(input, "me"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			vector<int> intvector;
			int Buffer;
			char end;
			do
			{
				scanf_s("%x", &Buffer);
				end = getchar();
				intvector.push_back(Buffer);
				// 结束符
				if (end == '!')
					break;
			} while (true);
			ChangeMemory(ProcessHandle, (LPVOID)addr, intvector);
		}
		// 修改寄存器的值
		else if (!strcmp(input, "re"))
		{
			//string Reg;
			char Reg[10] = {};
			scanf_s("%s", Reg,10);
			ChangeRegister(ThreadHandle, Reg);
		}
		// 修改汇编代码
		else if (!strcmp(input, "asm"))
		{
			int Addr = 0;
			scanf_s("%x", &Addr);
			ChangeAsm(Addr);
		}
		// dump，需要先清理掉所有的断点
		else if (!strcmp(input, "dump"))
		{
		Dump();
		}
		// 清除所有的断点
		else if (!strcmp(input, "deletebp"))
		{
			CBreakPoint::BreakPointList.clear();
		}
		// 获取帮助
		else if (!strcmp(input, "h"))
		{
		GetHelp();
		}
		// 否则返回错误
		else
		{
			printf("指令错误，请重新输入\n");
		}
	}
}


//******************************************************************************
// 函数名称: GetModules
// 函数说明: 获取加载模块，并列出来
// 作    者: lracker
// 时    间: 2019/10/25
// 返 回 值: BOOL
//******************************************************************************
BOOL CDebugger::GetModules()
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, DebugEvent.dwProcessId);
	if (hSnap == INVALID_HANDLE_VALUE)
		return FALSE;
	MODULEENTRY32 me = { sizeof(MODULEENTRY32) };
	if (!Module32First(hSnap, &me))
	{
		CloseHandle(hSnap);
		return FALSE;
	}
	do 
	{
		MyModule myModule;
		USES_CONVERSION;
		myModule.ModuleName = W2A(me.szModule);
		myModule.ModuleStartAddr = (DWORD64)me.modBaseAddr;
		myModule.ModuleEndAddr = (DWORD64)me.modBaseSize + myModule.ModuleStartAddr;
		myModule.szExePath = W2A(me.szExePath);
		MyModuleVector.push_back(myModule);
	} while (Module32Next(hSnap,&me));
}

//******************************************************************************
// 函数名称: GetRegister
// 函数说明: 查看寄存器信息，并且保存到容器里
// 作    者: lracker
// 时    间: 2019/10/25
// 参    数: HANDLE Handle
// 参    数: vector<string> & MyRegister
// 返 回 值: void
//******************************************************************************
void CDebugger::GetRegister(HANDLE hThread, vector<string>& MyRegisterVector)
{

	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ct);
	// 获取到 Dr7 寄存器，保存了哪些断点被使用
	PDBG_REG7 Dr7 = (PDBG_REG7)&ct.Dr7;
	PCHAR Buffer = new CHAR[20]();
	sprintf_s(Buffer, 20, "EAX = %08x  ", ct.Eax);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "EBX = %08x  ", ct.Ebx);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "ECX = %08x  ", ct.Ecx);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "EDX = %08x  ", ct.Edx);
	MyRegisterVector.push_back(Buffer);
	MyRegisterVector.push_back("\n");
	sprintf_s(Buffer, 20, "ESI = %08x  ", ct.Esi);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "EDI = %08x  ", ct.Edi);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "EIP = %08x  ", ct.Eip);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "ESP = %08x  ", ct.Esp);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "EBP = %08x  ", ct.Ebp);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "EFLAGS = %08x  ", ct.EFlags);
	MyRegisterVector.push_back(Buffer);
	MyRegisterVector.push_back("\n");
	sprintf_s(Buffer, 20, "CS = %04x       ", ct.SegCs);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "SS = %04x       ", ct.SegSs);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "DS = %04x       ", ct.SegDs);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "ES = %04x       ", ct.SegEs);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "FS = %04x       ", ct.SegFs);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "GS = %04x       ", ct.SegGs);
	MyRegisterVector.push_back(Buffer);
	MyRegisterVector.push_back("\n");
	sprintf_s(Buffer, 20, "Dr0 = %08x  ", ct.Dr0);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "Dr1 = %08x  ", ct.Dr1);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "Dr2 = %08x  ", ct.Dr2);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "Dr3 = %08x  ", ct.Dr3);
	MyRegisterVector.push_back(Buffer);
	MyRegisterVector.push_back("\n");
	sprintf_s(Buffer, 20, "L0 = %-9d  ", Dr7->L0);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "L1 = %-9d  ", Dr7->L1);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "L2 = %-9d  ", Dr7->L2);
	MyRegisterVector.push_back(Buffer);
	sprintf_s(Buffer, 20, "L3 = %-9d  ", Dr7->L3);
	MyRegisterVector.push_back(Buffer);
}

//******************************************************************************
// 函数名称: GetStack
// 函数说明: 获取dwCount条栈的信息,保存到容器里
// 作    者: lracker
// 时    间: 2019/10/25
// 参    数: HANDLE Handle
// 参    数: vector<string> & MyStackerVector
// 返 回 值: void
//******************************************************************************
void CDebugger::GetStack(HANDLE hProcess, HANDLE hThread, vector<string>& MyStackerVector)
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ct);
	BYTE Buff[512];
	DWORD dwRead = 0;
	ReadProcessMemory(hProcess, (LPVOID)ct.Esp, Buff, 512, &dwRead);
	PCHAR Buffer = new CHAR[9]();
	for (int i = 0; i < 10; ++i)
	{
		sprintf_s(Buffer, 9, "%08X", ((DWORD*)Buff)[i]);
		MyStackerVector.push_back(Buffer);
	}
}

//******************************************************************************
// 函数名称: GetMemory
// 函数说明: 用于查看内存信息
// 作    者: lracker
// 时    间: 2019/10/25
// 参    数: HANDLE hProcess
// 参    数: LPVOID Addr
// 返 回 值: void
//******************************************************************************
void CDebugger::GetMemory(HANDLE hProcess, LPVOID Addr)
{
	unsigned char* buff = new unsigned char[512]();
	// 读取指定长度的内存空间
	DWORD dwWrite = 0;
	ReadProcessMemory(hProcess, (LPVOID)Addr, buff, 512, &dwWrite);
	for (int i = 0; i < 512 && i < dwWrite; i++)
		printf("%02x ", buff[i]);
}

//******************************************************************************
// 函数名称: ChangeMemory
// 函数说明: 用于修改内存
// 作    者: lracker
// 时    间: 2019/10/28
// 参    数: HANDLE hProcess
// 参    数: LPVOID Addr
// 参    数: vector<int> intvector
// 返 回 值: void
//******************************************************************************
void CDebugger::ChangeMemory(HANDLE hProcess, LPVOID Addr, vector<int> intvector)
{
	int i = 0;
	for (auto it = intvector.begin(); it != intvector.end(); it++)
	{
		char tmp[3] = { 0 };
		sprintf_s(tmp, "%x", *it);
		BYTE n;
		// 16进制字符串转换一个字节的十六进制
		for (int i = 0; i < 2; i++)
		{
			if (tmp[i] >= '0' && tmp[i] <= '9')
				tmp[i] = tmp[i] - '0';
			else if (tmp[i] >= 'a' && tmp[i] <= 'f')
				tmp[i] = tmp[i] - 'W';
		}
		n = tmp[0] * 0x10 + tmp[1];
		WriteProcessMemory(hProcess, (LPVOID)((DWORD)Addr + i), &n, 1, NULL);
		i++;
	}
}

void CDebugger::ChangeRegister(HANDLE hThread, string Reg)
{
	CONTEXT context = { CONTEXT_INTEGER };
	GetThreadContext(hThread, &context);
	if (Reg == "eax")
	{
		int a = 0;
		scanf_s("%08x", &a);
		context.Eax = a;
	}
	else if (Reg == "ebx")
	{
		int a = 0;
		scanf_s("%08x", &a);
		context.Ebx = a;
	}
	else if (Reg == "ecx")
	{
		int a = 0;
		scanf_s("%08x", &a);
		context.Ecx = a;
	}
	else if (Reg == "edx")
	{
		int a = 0;
		scanf_s("%08x", &a);
		context.Edx = a;
	}
	else if (Reg == "edi")
	{
		int a = 0;
		scanf_s("%08x", &a);
		context.Edi = a;
	}
	else if (Reg == "esi")
	{
		int a = 0;
		scanf_s("%08x", &a);
		context.Esi = a;
	}
	SetThreadContext(hThread, &context);
}

//*****************************************************************************************
// 函数名称: RVATOFOA
// 函数说明: RVA转换为FOA
// 作    者: lracker
// 时    间: 2019/10/16
// 参    数: DWORD dwRVA
// 返 回 值: DWORD
//*****************************************************************************************
DWORD RVATOFOA(DWORD dwRVA)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)FileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD64)pDos);
	PIMAGE_FILE_HEADER pFile = (PIMAGE_FILE_HEADER)&pNt->FileHeader;
	DWORD dwNum = pFile->NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNt);
	DWORD dwOffset = 0;
	for (int i = 0; i < dwNum; i++)
	{
		// RVA大于该区段所在的RVA&&<=区段在文件中的大小+区段的RVA
		if (dwRVA >= pSectionHeader[i].VirtualAddress && dwRVA <= pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData)
		{
			dwOffset = dwRVA - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
			break;
		}
	}
	return dwOffset;
}

//******************************************************************************
// 函数名称: PrintfExport
// 函数说明: 打印出输出表
// 作    者: lracker
// 时    间: 2019/10/30
// 参    数: DWORD dwExportRVA
// 参    数: DWORD dwStart
// 返 回 值: void
//******************************************************************************
void PrintfExport(DWORD dwExportRVA, DWORD dwStart)
{
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(RVATOFOA(dwExportRVA) + (DWORD)FileBuff);
	DWORD dwFile = (DWORD)pExport - RVATOFOA(dwExportRVA);
	// 导出序号表
	WORD* pEOT = (WORD*)(RVATOFOA(pExport->AddressOfNameOrdinals) + (DWORD)dwFile);
	// 导出名称表
	DWORD* pENT = (DWORD*)(RVATOFOA(pExport->AddressOfNames) + (DWORD)dwFile);
	// 导出函数表
	DWORD* pEAT = (DWORD*)(RVATOFOA(pExport->AddressOfFunctions) + (DWORD)dwFile);
	for (int i = 0; i < pExport->NumberOfFunctions; i++)
	{
		// 打印出序号
		printf("输出 %d\t", i + pExport->Base);
		// 打印出地址
		printf("%X\t", pEAT[i] + dwStart);
		// 打印出名称
		for (int j = 0; j < pExport->NumberOfNames; j++)
		{
			if (i == pEOT[j])
			{
				// 函数名称
				printf("%s\n", RVATOFOA(pENT[j]) + dwFile);
				break;
			}
			else if (j == pExport->NumberOfNames - 1)
			{
				// 如果不是名称导入的话，那么就填-
				printf("-\n");
				break;
			}
		}
	}
}

void PrintImport(DWORD dwImportRVA, DWORD dwStart)
{
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(RVATOFOA(dwImportRVA) + (DWORD)FileBuff);
	DWORD dwFile = (DWORD)pImport - RVATOFOA(dwImportRVA);
	while (pImport->OriginalFirstThunk != NULL)
	{
		PIMAGE_THUNK_DATA32 pIat = (PIMAGE_THUNK_DATA32)(RVATOFOA(pImport->FirstThunk) + (DWORD)dwFile);
		ULONG ThunkRVA = pImport->OriginalFirstThunk;
		while (pIat->u1.Ordinal)
		{
			printf("输入  地址 %08X\t", ThunkRVA + dwStart);
			if (pIat->u1.Ordinal & 0x80000000)
			{
				printf("-\n");
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(RVATOFOA(pIat->u1.AddressOfData) + dwFile);
				printf("%s\n", pName->Name);
			}
			pIat++;
			ThunkRVA += 4;
		}
		pImport++;
	}
}

//******************************************************************************
// 函数名称: GetTable
// 函数说明: 根据序号获取模块的导入表导出表
// 作    者: lracker
// 时    间: 2019/10/29
// 参    数: int i
// 返 回 值: void
//******************************************************************************
void CDebugger::GetTable(int i)
{
	// 创建一个文件内核对象
	HANDLE hFile = CreateFileA(MyModuleVector[i].szExePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// 创建一个映射内核对象
	// 获取大小
	int nSize = GetFileSize(hFile, NULL);
	HANDLE hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, nSize, _T("PE"));
	// 将物理地址映射到虚拟地址
	FileBuff = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)FileBuff;
	PIMAGE_NT_HEADERS32 pNt = (PIMAGE_NT_HEADERS32)(pDos->e_lfanew + (DWORD)FileBuff);
	PIMAGE_FILE_HEADER pFile = (PIMAGE_FILE_HEADER)&pNt->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOpt = (PIMAGE_OPTIONAL_HEADER32)&pNt->OptionalHeader;
	// 获取导出表
	DWORD dwExportRVA = pOpt->DataDirectory[0].VirtualAddress;
	DWORD dwImportRVA = pOpt->DataDirectory[1].VirtualAddress;
	if (pOpt->DataDirectory[0].Size == 0)
	{
		printf("这个模块没有输出表\n");
		// return;
	}
	else
	{
		PrintfExport(dwExportRVA, MyModuleVector[i].ModuleStartAddr);
	}
	if (pOpt->DataDirectory[1].Size == 0)
	{
		printf("无法显示输入表\n");
		// return;
	}
	else
	{
		PrintImport(dwImportRVA, MyModuleVector[i].ModuleStartAddr);
	}
	CloseHandle(hFileMap);
}

//******************************************************************************
// 函数名称: GetHelp
// 函数说明: 获取帮助
// 作    者: lracker
// 时    间: 2019/10/30
// 返 回 值: void
//******************************************************************************
void CDebugger::GetHelp()
{
	printf("g\t直接跑起来\n");
	printf("u\t查看汇编\t格式: u 地址 条数\n");
	printf("r\t查看寄存器\n");
	printf("k\t查看栈信息\n");
	printf("m\t查看内存数据\t格式: m 地址\n");
	printf("lm\t查看模块信息\n");
	printf("mt\t查看模块的输入输出表\n");
	printf("dbp\t查看所有的CC断点\n");
	printf("bp\t下一个CC断点\t格式: bp 地址\n");
	printf("bd\t下一个条件断点\t格式: bd 地址 条件\n");
	printf("hxbp\t下一个硬件执行断点\t格式: hxbp 地址\n");
	printf("hwbp\t下一个硬件写入断点\t格式: hwbp 地址 字节数(1,2,4)\n");
	printf("hrwbp\t下一个硬件访问断点\t格式: hrwbp 地址 字节数(1,2,4)\n");
	printf("mrwbp\t下一个内存访问断点\t格式: mrwbp 地址\n");
	printf("mxbp\t下一个内存执行断点\t格式: mxbp 地址\n");
	printf("mwbp\t下一个内存写入断点\t格式: mwbp 地址\n");
	printf("t\t单步步入\n");
	printf("p\t单步步过\n");
	printf("me\t修改内存的值\t格式: me 地址 Opcode!(!作为结束符)\n");
	printf("re\t修改寄存器的值\t格式: r 寄存器 值\n");
	printf("asm\t修改汇编代码\t");
}

// 打印opcode
void printOpcode(const unsigned char* pOpcode, int nSize)
{
	for (int i = 0; i < nSize; ++i)
	{
		printf("%02X ", pOpcode[i]);
	}
	printf("\n");
}

//******************************************************************************
// 函数名称: ChangeAsm
// 函数说明: 修改汇编代码
// 作    者: lracker
// 时    间: 2019/10/30
// 返 回 值: void
//******************************************************************************
void CDebugger::ChangeAsm(int Addr)
{
	// 初始化汇编引擎
	ks_engine* pengine = NULL;
	ks_open(KS_ARCH_X86, KS_MODE_32, &pengine);
	unsigned char* opcode = NULL; // 汇编得到的opcode的缓冲区首地址
	unsigned int nOpcodeSize = 0; // 汇编出来的opcode的字节数
	printf("请输入指令的条数\n");
	int n = 0;
	scanf_s("%d", &n);
	getchar();
	printf("请输入指令，用分号隔开，最后不用加分号！\n");
	char* asmCode = (char*)malloc(n * 16);
	memset(asmCode, 0, n * 16);
	scanf_s("%[^\n]", asmCode, n * 16);
	int nRet = 0; // 保存函数的返回值，用于判断函数是否执行成功
	size_t stat_count = 0; // 保存成功汇编的指令的条数

	nRet = ks_asm(pengine, /* 汇编引擎句柄，通过ks_open函数得到*/
		asmCode, /*要转换的汇编指令*/
		Addr, /*汇编指令所在的地址*/
		&opcode,/*输出的opcode*/
		&nOpcodeSize,/*输出的opcode的字节数*/
		&stat_count /*输出成功汇编的指令的条数*/
	);

	// 返回值等于-1时反汇编错误
	if (nRet == -1)
	{
		// 输出错误信息
		// ks_errno 获得错误码
		// ks_strerror 将错误码转换成字符串，并返回这个字符串
		printf("错误信息：%s\n", ks_strerror(ks_errno(pengine)));
		return;
	}
	WriteProcessMemory(ProcessHandle, (LPVOID)Addr, opcode, nOpcodeSize, NULL);
	printf("一共转换了%d条指令\n", stat_count);
	// 打印汇编出来的opcode
	printOpcode(opcode, nOpcodeSize);
	// 释放空间
	ks_free(opcode);

	// 关闭句柄
	ks_close(pengine);
}

void CDebugger::Dump()
{
	LPCSTR str = "dump.exe";
	HANDLE hFile = CreateFileA(str, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("创建失败");
		if (GetLastError() == 0x00000050) {
			printf("文件已存在");
		}
		return;
	}
	IMAGE_DOS_HEADER dos;//dos头

	IMAGE_NT_HEADERS nt;
	//读dos头
	LPVOID imgBase = (LPVOID)0x400000;
	HANDLE Hprocess = g_hProcess;

	char* szBuff = (char*)malloc(0x1000);
	ZeroMemory(szBuff, 0x1000);
	ReadProcessMemory(Hprocess, imgBase, szBuff, 0x1000, NULL);
	if (ReadProcessMemory(Hprocess,
		(BYTE*)imgBase, &dos, sizeof(IMAGE_DOS_HEADER), NULL) == FALSE)
		return;


	//读nt头
	if (ReadProcessMemory(Hprocess, (BYTE*)imgBase + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL) == FALSE)
	{
		return;
	}


	//读取区块并计算区块大小
	DWORD secNum = nt.FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Sections = new IMAGE_SECTION_HEADER[secNum];
	//读取区块
	if (ReadProcessMemory(Hprocess,
		(BYTE*)imgBase + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS),
		Sections,
		secNum * sizeof(IMAGE_SECTION_HEADER),
		NULL) == FALSE)
	{
		return;
	}

	//计算所有区块的大小
	DWORD allsecSize = 0;
	DWORD maxSec;//最大的区块

	maxSec = 0;

	for (int i = 0; i < secNum; ++i)
	{
		allsecSize += Sections[i].SizeOfRawData;

	}

	//区块总大小
	DWORD topsize = secNum * sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_NT_HEADERS) + dos.e_lfanew;

	//使头大小按照文件对齐
	if ((topsize & nt.OptionalHeader.FileAlignment) != topsize)
	{
		topsize &= nt.OptionalHeader.FileAlignment;
		topsize += nt.OptionalHeader.FileAlignment;
	}

	DWORD ftsize = topsize + allsecSize;
	//创建文件映射
	HANDLE hMap = CreateFileMapping(hFile,
		NULL, PAGE_READWRITE,
		0,
		ftsize,
		0);

	if (hMap == NULL)
	{
		printf("创建文件映射失败\n");
		return;
	}

	//创建视图
	LPVOID lpmem = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

	if (lpmem == NULL)
	{
		delete[] Sections;
		CloseHandle(hMap);
		printf("创建失败\n");
		return;
	}
	PBYTE bpMem = (PBYTE)lpmem;
	memcpy(lpmem, &dos, sizeof(IMAGE_DOS_HEADER));
	//计算dossub 大小

	DWORD subSize = dos.e_lfanew - sizeof(IMAGE_DOS_HEADER);

	if (ReadProcessMemory(Hprocess, (BYTE*)imgBase + sizeof(IMAGE_DOS_HEADER), bpMem + sizeof(IMAGE_DOS_HEADER), subSize, NULL) == FALSE)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		return;
	}

	nt.OptionalHeader.ImageBase = (DWORD)imgBase;
	//保存NT头
	memcpy(bpMem + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS));

	//保存区块
	memcpy(bpMem + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS), Sections, secNum * sizeof(IMAGE_SECTION_HEADER));

	for (int i = 0; i < secNum; ++i)
	{
		if (ReadProcessMemory(
			Hprocess, (BYTE*)imgBase + Sections[i].VirtualAddress,
			bpMem + Sections[i].PointerToRawData,
			Sections[i].SizeOfRawData,
			NULL) == FALSE)
		{
			delete[] Sections;
			CloseHandle(hMap);
			UnmapViewOfFile(lpmem);
			return;
		}
	}
	if (FlushViewOfFile(lpmem, 0) == false)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		printf("保存到文件失败\n");
		return;
	}
	delete[] Sections;
	CloseHandle(hMap);
	UnmapViewOfFile(lpmem);
	printf("dump成功");
	return;

}
