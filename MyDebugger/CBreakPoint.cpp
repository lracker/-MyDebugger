#include "CBreakPoint.h"
#include "CCapstone.h"
#include <tchar.h>

// 维护一个断点列表，保存所有的软件断点信息
vector<BREAKPOINTINFO> CBreakPoint::BreakPointList;
int CBreakPoint::nDR6 = 0;
BOOL CBreakPoint::CCChange = FALSE;
BOOL CBreakPoint::HWChange = FALSE;
// 判断是否因为内存断点引起的单步
BOOL CBreakPoint::MemChange = FALSE;
//******************************************************************************
// 函数名称: SetStepBreakPoint
// 函数说明: 设置单步步过断点，如果是碰到了call和reop。则往后走两几步下CC断点，
//			 否则就是TF断点
// 作    者: lracker
// 时    间: 2019/10/27
// 参    数: HANDLE hThread
// 返 回 值: void
//******************************************************************************
void CBreakPoint::SetStepBreakPoint(HANDLE hProcess, HANDLE hThread)
{
	// 获取当前eip指向的位置是否指向的是call或rep
	// 首先获取eip
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ct);
	DWORD Addr = ct.Eip;
	// 然后读取EIP指向的位置的第一个字节
	PCHAR mnemonic;
	CHAR REP[4] = {};
	int nLen = 0;
	// 获取指令和长度
	CCapstone::GetADisAsm(hProcess, (LPVOID)Addr, mnemonic, nLen);
	strncpy_s(REP, 4, mnemonic, 3);
	// 如果是call指令或者rep指令的的话
	if (!strcmp(mnemonic,"call")|| !strcmp(REP,"rep"))
	{
		// 往下一条指令的位置设置CC断点，一次性的，一会儿自动删掉的 
		CBreakPoint::SetCCBreakPoint(hProcess, (LPVOID)(Addr + nLen), TRUE);
	}
	// 否则就单步步入断点就好了，就设置为tf断点
	else
	{
		CBreakPoint::SetTFBreakPoint(hThread);
	}
}

//******************************************************************************
// 函数名称: SetTFBreakPoint
// 函数说明: 设置单步断点(TF断点)
// 作    者: lracker
// 时    间: 2019/10/25
// 参    数: HANDLE hThread
// 返 回 值: void
//******************************************************************************
void CBreakPoint::SetTFBreakPoint(HANDLE hThread)
{
	// 获取线程环境块
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ct);
	// 将TF标志位设置为1
	ct.EFlags |= 0x100;	
	SetThreadContext(hThread, &ct);
}

//******************************************************************************
// 函数名称: SetCCBreakPoint
// 函数说明: 设置一个软件断点,0xCC
// 作    者: lracker
// 时    间: 2019/10/25
// 参    数: HANDLE hProcess
// 参    数: LPVOID Addr
// 返 回 值: void
//******************************************************************************
void CBreakPoint::SetCCBreakPoint(HANDLE hProcess, LPVOID Addr, BOOL Delete)
{
	// 往指定地址的第一个字节里写入0xCC
	// 创建保存断点信息的结构体
	BREAKPOINTINFO info = { Addr };
	// 读取该地址的第一个字节，并且保存到结构体里
	ReadProcessMemory(hProcess, Addr, &info.old_opcode, 1, NULL);
	// 往里面写入0xCC
	WriteProcessMemory(hProcess, Addr, "\xCC", 1, NULL);
	// 代表了这是永久断点
	info.Delete = Delete;
	// 将设置的断点保存到链表里
	CBreakPoint::BreakPointList.push_back(info);
}

//******************************************************************************
// 函数名称: IsCondition
// 函数说明: 判断该断点的条件是否成立
// 作    者: lracker
// 时    间: 2019/10/28
// 参    数: HANDLE hThread
// 参    数: LPVOID Addr
// 返 回 值: void
//******************************************************************************
BOOL CBreakPoint::IsCondition(HANDLE hThread, LPVOID Addr)
{
	for(auto&i:CBreakPoint::BreakPointList)
	{
		if (i.addr == Addr)
		{
			int RegValue = 0;
			CONTEXT ct = { CONTEXT_INTEGER };
			GetThreadContext(hThread, &ct);
			// 判断是哪一个寄存器
			if (i.Reg == "eax")
			{
				RegValue = ct.Eax;
			}
			else if (i.Reg == "ebx")
			{
				RegValue = ct.Ebx;
			}
			else if (i.Reg == "ecx")
			{
				RegValue = ct.Ecx;
			}
			else if (i.Reg == "edx")
			{
				RegValue = ct.Edx;
			}
			else if (i.Reg == "edi")
			{
				RegValue = ct.Edi;
			}
			else if (i.Reg == "esi")
			{
				RegValue = ct.Esi;
			}
			else
			{
				return TRUE;
			}
			// 判断是什么符号了
			if (i.Operator == "==")
			{
				if (i.nValue == RegValue)
				{
					return TRUE;
				}
				return FALSE;
			}
			if (i.Operator == ">=")
			{
				if (i.nValue >= RegValue)
				{
					return TRUE;
				}
				return FALSE;
			}
			if (i.Operator == "<=")
			{
				if (i.nValue <= RegValue)
				{
					return TRUE;
				}
				return FALSE;
			}
			if (i.Operator == "!=")
			{
				if (i.nValue != RegValue)
				{
					return TRUE;
				}
				return FALSE;
			}
			if (i.Operator == ">")
			{
				if (i.nValue > RegValue)
				{
					return TRUE;
				}
				return FALSE;
			}
			if (i.Operator == "<")
			{
				if (i.nValue < RegValue)
				{
					return TRUE;
				}
				return FALSE;
			}
			else
			{
				return FALSE;
			}
		}
	}
}

//******************************************************************************
// 函数名称: FixCCBreakPoint
// 函数说明: 修复一个软件断点，因为要还原
// 作    者: lracker
// 时    间: 2019/10/25
// 参    数: HANDLE hProcess
// 参    数: LPVOID Addr
// 返 回 值: void
//******************************************************************************
void CBreakPoint::FixCCBreakPoint(HANDLE hProcess, HANDLE hThread, LPVOID Addr)
{
	// 遍历断点列表
	for (int i = 0; i < CBreakPoint::BreakPointList.size(); ++i)
	{
		if (CBreakPoint::BreakPointList[i].addr == Addr)
		{
			// 1. 获取寄存器信息，将 eip - 1
			CONTEXT context = { CONTEXT_CONTROL };
			GetThreadContext(hThread, &context);
			context.Eip -= 1;
			SetThreadContext(hThread, &context);
			// 这里只是修复一下opcode而已，并没有从断点列表中删除。
			WriteProcessMemory(hProcess, Addr, &CBreakPoint::BreakPointList[i].old_opcode, 1, NULL);
			// 设置标志，表示接下来要重新设置回CC
			CBreakPoint::CCChange = TRUE;
			// 如果是要删除这个断点的话，那就从列表中删掉他
			if (CBreakPoint::BreakPointList[i].Delete)
			{
				BreakPointList.erase(BreakPointList.begin() + i);
				CBreakPoint::CCChange = FALSE;
			}
			break;
		}
	}
	
}

//******************************************************************************
// 函数名称: ResetCCBreakPoint
// 函数说明: 遍历断点列表并重新设置为CC
// 作    者: lracker
// 时    间: 2019/10/26
// 参    数: HANDLE hProcess
// 参    数: LPVOID Addr
// 返 回 值: void
//******************************************************************************
void CBreakPoint::ResetCCBreakPoint(HANDLE hProcess)
{
	for (auto& i : BreakPointList)
	{
		WriteProcessMemory(hProcess, i.addr, "\xCC", 1, NULL);
	}
	// 把标志改回来，表示已经重新设置为CC了
	CBreakPoint::CCChange = FALSE;
}

//******************************************************************************
// 函数名称: SetHXBreakPoint
// 函数说明: 设置一个硬件断点
// 作    者: lracker
// 时    间: 2019/10/25
// 参    数: HANDLE hProcess
// 参    数: HANDLE hThread
// 参    数: LPVOID Addr
// 返 回 值: void
//******************************************************************************
void CBreakPoint::SetHWBreakPoint(HANDLE hThread, LPVOID Addr, CHAR Type, DWORD dwLen)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	// 获取线程环境块
	GetThreadContext(hThread, &ct);
	// 如果不是执行断点的话
	// 那么要根据长度进行地址对齐
	if (Type != 0)
	{ 
		dwLen--;
		// 1字节
		if (dwLen == 0)
		{
			Addr = Addr;
		}
		// 2字节对齐粒度
		else if (dwLen == 1)	
		{
			Addr = (LPVOID)((DWORD)Addr - (DWORD)Addr % 2);
		}
		// 4字节对齐
		else if (dwLen == 3)
		{
			Addr = (LPVOID)((DWORD)Addr - (DWORD)Addr % 4);
		}
		else
		{
			printf("长度有误，只能为1，2，4\n");
			return;
		}
	}
	PDBG_REG7 pDr7 = (PDBG_REG7)&ct.Dr7;
	// 假如DR0没有被使用
	if (pDr7->L0 == 0)
	{
		ct.Dr0 = (DWORD)Addr;
		pDr7->RW0 = Type;
		pDr7->LEN0 = dwLen;
		pDr7->L0 = 1;
	}
	else if (pDr7->L1 == 0)
	{
		ct.Dr1 = (DWORD)Addr;
		pDr7->RW1 = Type;
		pDr7->LEN1 = dwLen;
		pDr7->L1 = 1;
	}
	else if (pDr7->L2 == 0)
	{
		ct.Dr2 = (DWORD)Addr;
		pDr7->RW2 = Type;
		pDr7->LEN2 = dwLen;
		pDr7->L2 = 1;
	}
	else if (pDr7->L3 == 0)
	{
		ct.Dr3 = (DWORD)Addr;
		pDr7->RW3 = Type;
		pDr7->LEN3 = dwLen;
		pDr7->L3 = 1;
	}
	else
	{
		printf("没有空闲的硬件断点位置!\n");
	}
	SetThreadContext(hThread, &ct);
}

//******************************************************************************
// 函数名称: FixHWBreakPoint
// 函数说明: 修复断点
// 作    者: lracker
// 时    间: 2019/10/26
// 参    数: HANDLE hThread
// 返 回 值: void
//******************************************************************************
void CBreakPoint::FixHWBreakPoint(HANDLE hThread)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);
	// 获取到 Dr7 寄存器，保存了哪些断点被使用
	PDBG_REG7 Dr7 = (PDBG_REG7)&ct.Dr7;
	CBreakPoint::nDR6 = ct.Dr6 & 0xf;
	switch (nDR6)
	{
	case 1:
		Dr7->L0 = 0;
		CBreakPoint::HWChange = TRUE;
		break;
	case 2:
		Dr7->L1 = 0;
		CBreakPoint::HWChange = TRUE;
		break;
	case 3:
		Dr7->L2 = 0;
		CBreakPoint::HWChange = TRUE;
		break;
	case 4:
		Dr7->L3 = 0;
		CBreakPoint::HWChange = TRUE;
		break;
	}
	SetThreadContext(hThread, &ct);
}

//******************************************************************************
// 函数名称: ResetHWBreakPoint
// 函数说明: 重新设置硬件断点
// 作    者: lracker
// 时    间: 2019/10/26
// 参    数: HANDLE hThread
// 返 回 值: void
//******************************************************************************
void CBreakPoint::ResetHWBreakPoint(HANDLE hThread)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);
	// 获取到 Dr7 寄存器，保存了哪些断点被使用
	PDBG_REG7 Dr7 = (PDBG_REG7)&ct.Dr7;
	switch (CBreakPoint::nDR6)
	{
	case 1:
		Dr7->L0 = 1;
		break;
	case 2:
		Dr7->L1 = 1;
		break;
	case 3:
		Dr7->L2 = 1;
		break;
	case 4:
		Dr7->L3 = 1;
		break;
	}
	SetThreadContext(hThread, &ct);
	CBreakPoint::HWChange = FALSE;
}

//******************************************************************************
// 函数名称: SetMemBreakPoint
// 函数说明: 设置一个内存执行断点 
// 作    者: lracker
// 时    间: 2019/10/25
// 参    数: HANDLE hProcess
// 参    数: LPVOID Addr
// 返 回 值: void
//******************************************************************************
void CBreakPoint::SetMemBreakPoint(HANDLE hProcess, LPVOID Addr, DWORD64& MemAddr, DWORD& dwOldProtect, DWORD flNewProtect)
{
	// 先保存要下载内存断点的位置
	MemAddr = (DWORD64)Addr;
	// 获取所在页面的起始位置
	DWORD64 StartAddr = (DWORD64)Addr & 0xFFFFF000;
	// 设置为PAGE_NOACCESS
	VirtualProtectEx(hProcess, (LPVOID)StartAddr, 0x1000, flNewProtect, &dwOldProtect);
	return;
}
//******************************************************************************
// 函数名称: RecoverOpcode
// 函数说明: 恢复所有的CC断点opcode
// 作    者: lracker
// 时    间: 2019/10/27
// 返 回 值: void
//******************************************************************************
void CBreakPoint::RecoverOpcode(HANDLE hProcess)
{
	for (auto& i : CBreakPoint::BreakPointList)
	{
		
		WriteProcessMemory(hProcess, i.addr, &i.old_opcode, 1, NULL);
	}
}

//******************************************************************************
// 函数名称: RecoverCC
// 函数说明: 设置所有CC断点为CC
// 作    者: lracker
// 时    间: 2019/10/27
// 参    数: HANDLE hProcess
// 返 回 值: void
//******************************************************************************
void CBreakPoint::RecoverCC(HANDLE hProcess, HANDLE hThread, LPVOID Addr)
{
	for (auto& i : CBreakPoint::BreakPointList)
	{
		// 假如此刻查看的地方刚好是EIP指向的位置，
		// 也就是刚好EIP指向的位置刚好有CC断点
		// 那么就不用修复回CC了，因为下一步就会修复了。
		// 如果这里修复了的话就不会跑起来的。
		// 获取线程环境块
		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &ct);
		if (ct.Eip == (DWORD)i.addr)
			break;
		WriteProcessMemory(hProcess, i.addr, "\xCC", 1, NULL);
	}
	
}

//******************************************************************************
// 函数名称: ConditionCCBreakPoint
// 函数说明: 设置一个条件断点
// 作    者: lracker
// 时    间: 2019/10/28
// 参    数: HANDLE hProcess
// 参    数: LPVOID Addr
// 参    数: string condition
// 返 回 值: void
//******************************************************************************
void CBreakPoint::ConditionCCBreakPoint(HANDLE hProcess, LPVOID Addr, PCHAR pReg, PCHAR pOperator,int nValue)
{
	// 首先判断一下是否已经写过这个条件断点了
	for (auto& i : CBreakPoint::BreakPointList)
	{
		if (i.addr == Addr)
		{
			// 如果已经有这个断点了，则更新条件
			i.Reg = pReg;
			i.Operator = pOperator;
			i.nValue = nValue;
			return;
		}
	}
	// 往指定地址的第一个字节里写入0xCC
	// 创建保存断点信息的结构体
	BREAKPOINTINFO info = { Addr };
	info.Reg = pReg;
	info.Operator = pOperator;
	info.nValue = nValue;
	// 读取该地址的第一个字节，并且保存到结构体里
	ReadProcessMemory(hProcess, Addr, &info.old_opcode, 1, NULL);
	// 往里面写入0xCC
	WriteProcessMemory(hProcess, Addr, "\xCC", 1, NULL);
	// 代表了这是永久断点
	info.Delete = FALSE;
	// 将设置的断点保存到链表里
	CBreakPoint::BreakPointList.push_back(info);
}

