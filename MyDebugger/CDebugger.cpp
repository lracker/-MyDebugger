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

#define DLLPATH "C:\\Users\\Canary\\Desktop\\15PB\\�ڶ��׶�\\MyDebugger\\HookNtQueryInformation.dll"
LPVOID FileBuff = nullptr;
BOOL First = TRUE;
BOOL Initiative = FALSE;
BOOL ReadWrite = FALSE;
HANDLE g_hProcess = NULL;
using PFUNC1 = void(*)(char*);
using PFUNC2 = void(*)(HANDLE hProcess, const char* DllPath);
//******************************************************************************
// ��������: Open
// ����˵��: ����һ��·�����Ե��Եķ�ʽ��������
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// ��    ��: LPCSTR FilePath
// �� �� ֵ: void
//******************************************************************************
void CDebugger::Open(LPCSTR FilePath)
{
	// ������̴����ɹ������ڽ��ս����̵߳ľ����ID
	PROCESS_INFORMATION ProcessInfo = { 0 };
	STARTUPINFOA StartupInfo = { sizeof(STARTUPINFO) };
	// �Ե��Է�ʽ��������
	BOOL result = CreateProcessA(FilePath, nullptr, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInfo);
	if (result == TRUE)
	{
		// �������,ʹ�ò����������
		for (auto& i : PluginsVector)
		{
			// �ҵ����MyNtQueryInformationProcess.dll
			if (!strcmp(i.name, "AntiDebug.dll"))
			{
				// ���ò����Run����
				PFUNC2 Func = (PFUNC2)GetProcAddress(i.Base, "Run");
				if (Func)
				{
					Func(ProcessInfo.hProcess, DLLPATH);
					break;
				}
			}
		}
		g_hProcess = ProcessInfo.hProcess;
		// ���ص��Է���
		CloseHandle(ProcessInfo.hThread);
	//	CloseHandle(ProcessInfo.hProcess);
	}
	// ��ʼ�����������
	CCapstone::Init();
}

//******************************************************************************
// ��������: Run
// ����˵��: ���ղ���������¼�
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// �� �� ֵ: void
//******************************************************************************
void CDebugger::Run()
{
	BOOL First = TRUE;
	// ͨ��ѭ�����ϵĴӵ��Զ����л�ȡ��������Ϣ
	while (WaitForDebugEvent(&DebugEvent, INFINITE))
	{
		OpenHandles();
		switch (DebugEvent.dwDebugEventCode)
		{
			// �쳣�����¼�
		case EXCEPTION_DEBUG_EVENT:
			OnExceptionEvent();
			break;
			// ���̴����¼�
		case CREATE_PROCESS_DEBUG_EVENT:
		{
			// ��ȡOEP����
			LPVOID OEPEntry = DebugEvent.u.CreateProcessInfo.lpStartAddress;
			// Ȼ������һ��CC�ϵ㣬һ���Եģ�һ����Զ�ɾ����
			CBreakPoint::SetCCBreakPoint(ProcessHandle, OEPEntry, TRUE);
			break;
		}
		}
		CloseHandles();
		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, dwCountinueStatus);
	}
}

//******************************************************************************
// ��������: InitPlugin
// ����˵��: ���ز����
// ��    ��: lracker
// ʱ    ��: 2019/10/29
// �� �� ֵ: void
//******************************************************************************
void CDebugger::InitPlugin()
{
	string PluginPath = "plugin/";
	string PFindPluginPath = "plugin/*.dll";
	// ������������ļ���Ϣ
	WIN32_FIND_DATAA FileInfo = { 0 };
	// ���������·�����������ú�׺��
	HANDLE FindHandle = FindFirstFileA(PFindPluginPath.c_str(), &FileInfo);
	// һ��һ������
	do {
		string FilePath = PluginPath + FileInfo.cFileName;
		// ����DLL�ļ������ұ��浽һ������
		HMODULE Handle = LoadLibraryA(FilePath.c_str());
		// ���ģ����سɹ�����Ҫ����ṩ�Լ�����Ϣ����ʽ�ǵ���һ���ض��ĺ���
		if (Handle)
		{
			PLGINFO info = { Handle };
			PFUNC1 func = (PFUNC1)GetProcAddress(Handle, "Init");
			// ���������ȡ�ɹ�
			if (func)
			{
				func(info.name);
				PluginsVector.push_back(info);
				printf("���%s�Ѿ�������\n", info.name);
			}
		}
	} while (FindNextFileA(FindHandle, &FileInfo));
	FindClose(FindHandle);


}


//******************************************************************************
// ��������: OpenHandles
// ����˵��: �ṩ�������ڴ�Ŀ����̾��
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// �� �� ֵ: void
//******************************************************************************
void CDebugger::OpenHandles()
{
	ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
}

//******************************************************************************
// ��������: CloseHandles
// ����˵��:�ṩ�������ڹرվ��
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// �� �� ֵ: void
//******************************************************************************
void CDebugger::CloseHandles()
{
	CloseHandle(ThreadHandle);
	CloseHandle(ProcessHandle);
}

//******************************************************************************
// ��������: OnExceptionEvent
// ����˵��: ���ڴ�����յ��������쳣�¼�
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// �� �� ֵ: void
//******************************************************************************
void CDebugger::OnExceptionEvent()
{
	// ��ȡ�쳣�����ĵ�ַ�Լ��쳣������
	DWORD dwCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID Addr = DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	// ����쳣����Ϣ�Ͳ�����λ��
	// ���������g���������ĵ����쳣�Ļ����Ͳ���ʾ��
	if(!Initiative)
		printf("Type(%08X): %p\n", dwCode, Addr);
	switch (dwCode)
	{
		// �豸�����쳣�����ڴ�ϵ����
	case EXCEPTION_ACCESS_VIOLATION:
	{

		DWORD64 MemAddrStart = m_MemAddr & 0xFFFFF000;
		// �ı�ҳ������
		VirtualProtectEx(ProcessHandle, (LPVOID)MemAddrStart, 0x1000, m_dwOldProtect, &m_dwOldProtect);
		CBreakPoint::MemChange = TRUE;
		Initiative = TRUE;
		// �ж��Ƿ�����һҳ��
		if ((DWORD64)Addr >= MemAddrStart && (DWORD64)Addr <= (MemAddrStart + 0x1000))
		{
			// �ڴ�ִ�жϵ�
			CBreakPoint::SetTFBreakPoint(ThreadHandle);
			ReadWrite = FALSE;
			return;
		}
		else
		{
			// �ڴ���ʶϵ�
			CBreakPoint::SetCCBreakPoint(ProcessHandle, Addr, TRUE);
			ReadWrite = TRUE;
			return;
		}
		break;
	}
	// �ϵ��쳣: int 3(0xCC)�ᴥ�����쳣
	case EXCEPTION_BREAKPOINT:
	{
		// �����̱�������ʱ�򣬲���ϵͳ���⵱ǰ��
		// �����Ƿ��ڱ�����״̬������������ˣ���
		// ��ͨ�� int 3 ����һ������ϵ㣬����ϵ�
		// ͨ������Ҫ����
		if (First)
		{
			Addr = (char*)Addr + 1;
			First = FALSE;
		}
		// �����������������õ� int 3�ϵ㣬��Ҫ���д���
		else
		{			
			CBreakPoint::FixCCBreakPoint(ProcessHandle, ThreadHandle, Addr);
			// �����ж�һ�¶ϵ�������Ƿ���� 
			// ��������Ļ������������
			// ���򲻶�������
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
	// Ӳ���ϵ��¼�: TF������ DrN�ϵ�
	case EXCEPTION_SINGLE_STEP:
	{	// ��ȡ�̻߳����飬������
		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(ThreadHandle, &ct);
		// ������ڴ�ϵ�ı���״̬
		if (CBreakPoint::MemChange)
		{
			DWORD64 MemAddrStart = m_MemAddr & 0xFFFFF000;
			VirtualProtectEx(ProcessHandle, (LPVOID)MemAddrStart, 0x1000, m_dwOldProtect, &m_dwOldProtect);
			CBreakPoint::MemChange = FALSE;
			if (Initiative)
			{
				Initiative = FALSE;
			}
			// ������ڴ���ʶϵ�Ļ�
			if (ReadWrite)
			{
				return;
			}
		}
		if (CBreakPoint::CCChange)
		{
			// ���±���һ��CC�ϵ��б�
			CBreakPoint::ResetCCBreakPoint(ProcessHandle);
			if (Initiative)
			{
				Initiative = FALSE;
				return;
			}
		}
		// ���Ӳ���ϵ�֮ǰ�ı���״̬��
		if (CBreakPoint::HWChange)
		{
			// ����������һ��Ӳ���ϵ�Ϊ����
			CBreakPoint::ResetHWBreakPoint(ThreadHandle);
			if (Initiative)
			{
				Initiative = FALSE;
				return;
			}
		}
		else
		{
			// ������Ӳ���ϵ�Ļ�����Ҫȡ
			CBreakPoint::FixHWBreakPoint(ThreadHandle);
		}
		break;
	}
	}
	// �鿴�����ǰ��Ҫ�����еĶϵ�ָ���ԭ����opcode
	CBreakPoint::RecoverOpcode(ProcessHandle);
	// Ӧ�ò鿴���� eip ָ���λ�ã��������쳣��λ��
	CCapstone::DisAsm(ProcessHandle, (LPVOID)((char*)Addr), 10);
	// ���귴������Ҫ�����еĶϵ�ָ���CC
	CBreakPoint::RecoverCC(ProcessHandle, ThreadHandle, (LPVOID)Addr);
	// ��ȡ�û���������
	GetCommend();
}

//******************************************************************************
// ��������: getCommend
// ����˵��: ��ȡ�û�������
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// �� �� ֵ: void
//******************************************************************************
void CDebugger::GetCommend()
{
	char input[0x100] = { 0 };
	while (TRUE)
	{
		printf(">>");
		// ��ȡָ�ָ��Ӧ�������ȿ��Ǻõ���
		scanf_s("%s", input, 0x100);
		// ���������ָ��ִ�в�ͬ�Ĳ���
		// ֱ��������
		if (!strcmp(input, "g"))
		{
			// �������룬�ó������ִ�У�ֱ������
			// ��������������һ���쳣
			// ���CC�ϵ��޸����ˣ�����������һ���쳣����������CC�ϵ�
			if (CBreakPoint::CCChange || CBreakPoint::HWChange || CBreakPoint::MemChange)
			{
				Initiative = TRUE;
				CBreakPoint::SetTFBreakPoint(ThreadHandle);
			}
			break;
		}
		// �鿴����࣬��ʽ��u ��ַ ����
		else if (!strcmp(input, "u"))
		{
			int addr = 0, lines = 0;
			scanf_s("%x %d", &addr, &lines);
			// �鿴�����ǰ��Ҫ�����еĶϵ�ָ���ԭ����opcode
			CBreakPoint::RecoverOpcode(ProcessHandle);
			CCapstone::DisAsm(ProcessHandle, (LPVOID)addr, lines);
			// ���귴������Ҫ�����еĶϵ�ָ���CC
			CBreakPoint::RecoverCC(ProcessHandle, ThreadHandle, (LPVOID)addr);
		}
		// �鿴�Ĵ���
		else if (!strcmp(input, "r"))
		{
			// ���������
			MyRegisterVector.clear();
			// ��ȡ�Ĵ�������Ϣ����������Ҵ�ӡ����
			GetRegister(ThreadHandle, MyRegisterVector);
			for (auto& i : MyRegisterVector)
			{
				printf("%s", i.c_str());
			}
			printf("\n");
		}
		// �鿴ջ��Ϣ
		else if (!strcmp(input, "k"))
		{
			// ��ȡջ��Ϣ��������
			MyStackVector.clear();
			GetStack(ProcessHandle, ThreadHandle, MyStackVector);
			for (auto& i : MyStackVector)
			{
				printf("%s\n", i.c_str());
			}
		}
		// �鿴�ڴ�����,��ʽ��m ��ַ
		else if (!strcmp(input, "m"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			// �����ڴ�ҳ
			GetMemory(ProcessHandle, (LPVOID)addr);
			printf("\n");
		}
		// �鿴ģ����Ϣ
		else if (!strcmp(input, "lm"))
		{
			MyModuleVector.clear();
			GetModules();
			printf("���    ");
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
		// �鿴ģ������������
		else if (!strcmp(input, "mt"))
		{
			printf("��������Ҫ�鿴��ģ������\n");
			int i = 0;
			scanf_s("%d", &i);
			GetTable(i - 1);
		}
		// �鿴���е�CC�ϵ�
		else if (!strcmp(input, "dbp"))
		{
			printf("CC�ϵ�����:\n");
			for (int i = 0; i < CBreakPoint::BreakPointList.size(); i++)
			{
				printf("��%d���ϵ�: %p\n", i + 1, CBreakPoint::BreakPointList[i].addr);
			}
		}
		// ��һ������ϵ�0xCC
		else if (!strcmp(input, "bp"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			CBreakPoint::SetCCBreakPoint(ProcessHandle, (LPVOID)addr, FALSE);
		}
		// ��һ�������ϵ�0xCC
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
		// ��һ��Ӳ��ִ�жϵ�
		else if (!strcmp(input, "hxbp"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			CBreakPoint::SetHWBreakPoint(ThreadHandle, (LPVOID)addr, 0, 0);
		}
		// ��һ��Ӳ��д��ϵ� ���ٸ��ֽ�
		// ��ʽ hwbp Addr nLen
		else if (!strcmp(input, "hwbp"))
		{
			int addr = 0, nLen = 0;
			scanf_s("%x %d", &addr, &nLen);
			CBreakPoint::SetHWBreakPoint(ThreadHandle, (LPVOID)addr, 1, nLen);
		}
		// ��һ��Ӳ������(��д)�ϵ� ���ٸ��ֽ�
		// ��ʽ hrwbp Addr nLen
		else if (!strcmp(input, "hrwbp"))
		{
			int addr = 0, nLen = 0;
			scanf_s("%x %d", &addr, &nLen);
			CBreakPoint::SetHWBreakPoint(ThreadHandle, (LPVOID)addr, 3, nLen);
		}
		// ��һ���ڴ����(��д)�ϵ�
		else if (!strcmp(input, "mrwbp"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			CBreakPoint::SetMemBreakPoint(ProcessHandle, (LPVOID)addr, m_MemAddr, m_dwOldProtect, PAGE_NOACCESS);
		}
		// ��һ���ڴ�д��ϵ�
		else if (!strcmp(input, "mwbp"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			CBreakPoint::SetMemBreakPoint(ProcessHandle, (LPVOID)addr, m_MemAddr, m_dwOldProtect, PAGE_READONLY);
		}
		// ��һ���ڴ�ִ�жϵ�
		else if (!strcmp(input, "mxbp"))
		{
			int addr = 0;
			scanf_s("%x", &addr);
			CBreakPoint::SetMemBreakPoint(ProcessHandle, (LPVOID)addr, m_MemAddr, m_dwOldProtect, PAGE_READWRITE);
		}
		// �������룬tf�ϵ�
		else if (!strcmp(input, "t"))
		{
			// ���ߵ����쳣�������������һ�������쳣�����µ�
			CBreakPoint::SetTFBreakPoint(ThreadHandle);
			break;
		}
		// ��������
		else if (!strcmp(input, "p"))
		{
			// ���õ�������
			CBreakPoint::SetStepBreakPoint(ProcessHandle, ThreadHandle);
			break;
		}
		// �޸��ڴ��ֵ
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
				// ������
				if (end == '!')
					break;
			} while (true);
			ChangeMemory(ProcessHandle, (LPVOID)addr, intvector);
		}
		// �޸ļĴ�����ֵ
		else if (!strcmp(input, "re"))
		{
			//string Reg;
			char Reg[10] = {};
			scanf_s("%s", Reg,10);
			ChangeRegister(ThreadHandle, Reg);
		}
		// �޸Ļ�����
		else if (!strcmp(input, "asm"))
		{
			int Addr = 0;
			scanf_s("%x", &Addr);
			ChangeAsm(Addr);
		}
		// dump����Ҫ����������еĶϵ�
		else if (!strcmp(input, "dump"))
		{
		Dump();
		}
		// ������еĶϵ�
		else if (!strcmp(input, "deletebp"))
		{
			CBreakPoint::BreakPointList.clear();
		}
		// ��ȡ����
		else if (!strcmp(input, "h"))
		{
		GetHelp();
		}
		// ���򷵻ش���
		else
		{
			printf("ָ���������������\n");
		}
	}
}


//******************************************************************************
// ��������: GetModules
// ����˵��: ��ȡ����ģ�飬���г���
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// �� �� ֵ: BOOL
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
// ��������: GetRegister
// ����˵��: �鿴�Ĵ�����Ϣ�����ұ��浽������
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// ��    ��: HANDLE Handle
// ��    ��: vector<string> & MyRegister
// �� �� ֵ: void
//******************************************************************************
void CDebugger::GetRegister(HANDLE hThread, vector<string>& MyRegisterVector)
{

	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ct);
	// ��ȡ�� Dr7 �Ĵ�������������Щ�ϵ㱻ʹ��
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
// ��������: GetStack
// ����˵��: ��ȡdwCount��ջ����Ϣ,���浽������
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// ��    ��: HANDLE Handle
// ��    ��: vector<string> & MyStackerVector
// �� �� ֵ: void
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
// ��������: GetMemory
// ����˵��: ���ڲ鿴�ڴ���Ϣ
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// ��    ��: HANDLE hProcess
// ��    ��: LPVOID Addr
// �� �� ֵ: void
//******************************************************************************
void CDebugger::GetMemory(HANDLE hProcess, LPVOID Addr)
{
	unsigned char* buff = new unsigned char[512]();
	// ��ȡָ�����ȵ��ڴ�ռ�
	DWORD dwWrite = 0;
	ReadProcessMemory(hProcess, (LPVOID)Addr, buff, 512, &dwWrite);
	for (int i = 0; i < 512 && i < dwWrite; i++)
		printf("%02x ", buff[i]);
}

//******************************************************************************
// ��������: ChangeMemory
// ����˵��: �����޸��ڴ�
// ��    ��: lracker
// ʱ    ��: 2019/10/28
// ��    ��: HANDLE hProcess
// ��    ��: LPVOID Addr
// ��    ��: vector<int> intvector
// �� �� ֵ: void
//******************************************************************************
void CDebugger::ChangeMemory(HANDLE hProcess, LPVOID Addr, vector<int> intvector)
{
	int i = 0;
	for (auto it = intvector.begin(); it != intvector.end(); it++)
	{
		char tmp[3] = { 0 };
		sprintf_s(tmp, "%x", *it);
		BYTE n;
		// 16�����ַ���ת��һ���ֽڵ�ʮ������
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
// ��������: RVATOFOA
// ����˵��: RVAת��ΪFOA
// ��    ��: lracker
// ʱ    ��: 2019/10/16
// ��    ��: DWORD dwRVA
// �� �� ֵ: DWORD
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
		// RVA���ڸ��������ڵ�RVA&&<=�������ļ��еĴ�С+���ε�RVA
		if (dwRVA >= pSectionHeader[i].VirtualAddress && dwRVA <= pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData)
		{
			dwOffset = dwRVA - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
			break;
		}
	}
	return dwOffset;
}

//******************************************************************************
// ��������: PrintfExport
// ����˵��: ��ӡ�������
// ��    ��: lracker
// ʱ    ��: 2019/10/30
// ��    ��: DWORD dwExportRVA
// ��    ��: DWORD dwStart
// �� �� ֵ: void
//******************************************************************************
void PrintfExport(DWORD dwExportRVA, DWORD dwStart)
{
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(RVATOFOA(dwExportRVA) + (DWORD)FileBuff);
	DWORD dwFile = (DWORD)pExport - RVATOFOA(dwExportRVA);
	// ������ű�
	WORD* pEOT = (WORD*)(RVATOFOA(pExport->AddressOfNameOrdinals) + (DWORD)dwFile);
	// �������Ʊ�
	DWORD* pENT = (DWORD*)(RVATOFOA(pExport->AddressOfNames) + (DWORD)dwFile);
	// ����������
	DWORD* pEAT = (DWORD*)(RVATOFOA(pExport->AddressOfFunctions) + (DWORD)dwFile);
	for (int i = 0; i < pExport->NumberOfFunctions; i++)
	{
		// ��ӡ�����
		printf("��� %d\t", i + pExport->Base);
		// ��ӡ����ַ
		printf("%X\t", pEAT[i] + dwStart);
		// ��ӡ������
		for (int j = 0; j < pExport->NumberOfNames; j++)
		{
			if (i == pEOT[j])
			{
				// ��������
				printf("%s\n", RVATOFOA(pENT[j]) + dwFile);
				break;
			}
			else if (j == pExport->NumberOfNames - 1)
			{
				// ����������Ƶ���Ļ�����ô����-
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
			printf("����  ��ַ %08X\t", ThunkRVA + dwStart);
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
// ��������: GetTable
// ����˵��: ������Ż�ȡģ��ĵ��������
// ��    ��: lracker
// ʱ    ��: 2019/10/29
// ��    ��: int i
// �� �� ֵ: void
//******************************************************************************
void CDebugger::GetTable(int i)
{
	// ����һ���ļ��ں˶���
	HANDLE hFile = CreateFileA(MyModuleVector[i].szExePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// ����һ��ӳ���ں˶���
	// ��ȡ��С
	int nSize = GetFileSize(hFile, NULL);
	HANDLE hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, nSize, _T("PE"));
	// �������ַӳ�䵽�����ַ
	FileBuff = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)FileBuff;
	PIMAGE_NT_HEADERS32 pNt = (PIMAGE_NT_HEADERS32)(pDos->e_lfanew + (DWORD)FileBuff);
	PIMAGE_FILE_HEADER pFile = (PIMAGE_FILE_HEADER)&pNt->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOpt = (PIMAGE_OPTIONAL_HEADER32)&pNt->OptionalHeader;
	// ��ȡ������
	DWORD dwExportRVA = pOpt->DataDirectory[0].VirtualAddress;
	DWORD dwImportRVA = pOpt->DataDirectory[1].VirtualAddress;
	if (pOpt->DataDirectory[0].Size == 0)
	{
		printf("���ģ��û�������\n");
		// return;
	}
	else
	{
		PrintfExport(dwExportRVA, MyModuleVector[i].ModuleStartAddr);
	}
	if (pOpt->DataDirectory[1].Size == 0)
	{
		printf("�޷���ʾ�����\n");
		// return;
	}
	else
	{
		PrintImport(dwImportRVA, MyModuleVector[i].ModuleStartAddr);
	}
	CloseHandle(hFileMap);
}

//******************************************************************************
// ��������: GetHelp
// ����˵��: ��ȡ����
// ��    ��: lracker
// ʱ    ��: 2019/10/30
// �� �� ֵ: void
//******************************************************************************
void CDebugger::GetHelp()
{
	printf("g\tֱ��������\n");
	printf("u\t�鿴���\t��ʽ: u ��ַ ����\n");
	printf("r\t�鿴�Ĵ���\n");
	printf("k\t�鿴ջ��Ϣ\n");
	printf("m\t�鿴�ڴ�����\t��ʽ: m ��ַ\n");
	printf("lm\t�鿴ģ����Ϣ\n");
	printf("mt\t�鿴ģ������������\n");
	printf("dbp\t�鿴���е�CC�ϵ�\n");
	printf("bp\t��һ��CC�ϵ�\t��ʽ: bp ��ַ\n");
	printf("bd\t��һ�������ϵ�\t��ʽ: bd ��ַ ����\n");
	printf("hxbp\t��һ��Ӳ��ִ�жϵ�\t��ʽ: hxbp ��ַ\n");
	printf("hwbp\t��һ��Ӳ��д��ϵ�\t��ʽ: hwbp ��ַ �ֽ���(1,2,4)\n");
	printf("hrwbp\t��һ��Ӳ�����ʶϵ�\t��ʽ: hrwbp ��ַ �ֽ���(1,2,4)\n");
	printf("mrwbp\t��һ���ڴ���ʶϵ�\t��ʽ: mrwbp ��ַ\n");
	printf("mxbp\t��һ���ڴ�ִ�жϵ�\t��ʽ: mxbp ��ַ\n");
	printf("mwbp\t��һ���ڴ�д��ϵ�\t��ʽ: mwbp ��ַ\n");
	printf("t\t��������\n");
	printf("p\t��������\n");
	printf("me\t�޸��ڴ��ֵ\t��ʽ: me ��ַ Opcode!(!��Ϊ������)\n");
	printf("re\t�޸ļĴ�����ֵ\t��ʽ: r �Ĵ��� ֵ\n");
	printf("asm\t�޸Ļ�����\t");
}

// ��ӡopcode
void printOpcode(const unsigned char* pOpcode, int nSize)
{
	for (int i = 0; i < nSize; ++i)
	{
		printf("%02X ", pOpcode[i]);
	}
	printf("\n");
}

//******************************************************************************
// ��������: ChangeAsm
// ����˵��: �޸Ļ�����
// ��    ��: lracker
// ʱ    ��: 2019/10/30
// �� �� ֵ: void
//******************************************************************************
void CDebugger::ChangeAsm(int Addr)
{
	// ��ʼ���������
	ks_engine* pengine = NULL;
	ks_open(KS_ARCH_X86, KS_MODE_32, &pengine);
	unsigned char* opcode = NULL; // ���õ���opcode�Ļ������׵�ַ
	unsigned int nOpcodeSize = 0; // ��������opcode���ֽ���
	printf("������ָ�������\n");
	int n = 0;
	scanf_s("%d", &n);
	getchar();
	printf("������ָ��÷ֺŸ���������üӷֺţ�\n");
	char* asmCode = (char*)malloc(n * 16);
	memset(asmCode, 0, n * 16);
	scanf_s("%[^\n]", asmCode, n * 16);
	int nRet = 0; // ���溯���ķ���ֵ�������жϺ����Ƿ�ִ�гɹ�
	size_t stat_count = 0; // ����ɹ�����ָ�������

	nRet = ks_asm(pengine, /* �����������ͨ��ks_open�����õ�*/
		asmCode, /*Ҫת���Ļ��ָ��*/
		Addr, /*���ָ�����ڵĵ�ַ*/
		&opcode,/*�����opcode*/
		&nOpcodeSize,/*�����opcode���ֽ���*/
		&stat_count /*����ɹ�����ָ�������*/
	);

	// ����ֵ����-1ʱ��������
	if (nRet == -1)
	{
		// ���������Ϣ
		// ks_errno ��ô�����
		// ks_strerror ��������ת�����ַ���������������ַ���
		printf("������Ϣ��%s\n", ks_strerror(ks_errno(pengine)));
		return;
	}
	WriteProcessMemory(ProcessHandle, (LPVOID)Addr, opcode, nOpcodeSize, NULL);
	printf("һ��ת����%d��ָ��\n", stat_count);
	// ��ӡ��������opcode
	printOpcode(opcode, nOpcodeSize);
	// �ͷſռ�
	ks_free(opcode);

	// �رվ��
	ks_close(pengine);
}

void CDebugger::Dump()
{
	LPCSTR str = "dump.exe";
	HANDLE hFile = CreateFileA(str, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("����ʧ��");
		if (GetLastError() == 0x00000050) {
			printf("�ļ��Ѵ���");
		}
		return;
	}
	IMAGE_DOS_HEADER dos;//dosͷ

	IMAGE_NT_HEADERS nt;
	//��dosͷ
	LPVOID imgBase = (LPVOID)0x400000;
	HANDLE Hprocess = g_hProcess;

	char* szBuff = (char*)malloc(0x1000);
	ZeroMemory(szBuff, 0x1000);
	ReadProcessMemory(Hprocess, imgBase, szBuff, 0x1000, NULL);
	if (ReadProcessMemory(Hprocess,
		(BYTE*)imgBase, &dos, sizeof(IMAGE_DOS_HEADER), NULL) == FALSE)
		return;


	//��ntͷ
	if (ReadProcessMemory(Hprocess, (BYTE*)imgBase + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL) == FALSE)
	{
		return;
	}


	//��ȡ���鲢���������С
	DWORD secNum = nt.FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Sections = new IMAGE_SECTION_HEADER[secNum];
	//��ȡ����
	if (ReadProcessMemory(Hprocess,
		(BYTE*)imgBase + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS),
		Sections,
		secNum * sizeof(IMAGE_SECTION_HEADER),
		NULL) == FALSE)
	{
		return;
	}

	//������������Ĵ�С
	DWORD allsecSize = 0;
	DWORD maxSec;//��������

	maxSec = 0;

	for (int i = 0; i < secNum; ++i)
	{
		allsecSize += Sections[i].SizeOfRawData;

	}

	//�����ܴ�С
	DWORD topsize = secNum * sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_NT_HEADERS) + dos.e_lfanew;

	//ʹͷ��С�����ļ�����
	if ((topsize & nt.OptionalHeader.FileAlignment) != topsize)
	{
		topsize &= nt.OptionalHeader.FileAlignment;
		topsize += nt.OptionalHeader.FileAlignment;
	}

	DWORD ftsize = topsize + allsecSize;
	//�����ļ�ӳ��
	HANDLE hMap = CreateFileMapping(hFile,
		NULL, PAGE_READWRITE,
		0,
		ftsize,
		0);

	if (hMap == NULL)
	{
		printf("�����ļ�ӳ��ʧ��\n");
		return;
	}

	//������ͼ
	LPVOID lpmem = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

	if (lpmem == NULL)
	{
		delete[] Sections;
		CloseHandle(hMap);
		printf("����ʧ��\n");
		return;
	}
	PBYTE bpMem = (PBYTE)lpmem;
	memcpy(lpmem, &dos, sizeof(IMAGE_DOS_HEADER));
	//����dossub ��С

	DWORD subSize = dos.e_lfanew - sizeof(IMAGE_DOS_HEADER);

	if (ReadProcessMemory(Hprocess, (BYTE*)imgBase + sizeof(IMAGE_DOS_HEADER), bpMem + sizeof(IMAGE_DOS_HEADER), subSize, NULL) == FALSE)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		return;
	}

	nt.OptionalHeader.ImageBase = (DWORD)imgBase;
	//����NTͷ
	memcpy(bpMem + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS));

	//��������
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
		printf("���浽�ļ�ʧ��\n");
		return;
	}
	delete[] Sections;
	CloseHandle(hMap);
	UnmapViewOfFile(lpmem);
	printf("dump�ɹ�");
	return;

}
