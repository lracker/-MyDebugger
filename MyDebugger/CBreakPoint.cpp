#include "CBreakPoint.h"
#include "CCapstone.h"
#include <tchar.h>

// ά��һ���ϵ��б��������е�����ϵ���Ϣ
vector<BREAKPOINTINFO> CBreakPoint::BreakPointList;
int CBreakPoint::nDR6 = 0;
BOOL CBreakPoint::CCChange = FALSE;
BOOL CBreakPoint::HWChange = FALSE;
// �ж��Ƿ���Ϊ�ڴ�ϵ�����ĵ���
BOOL CBreakPoint::MemChange = FALSE;
//******************************************************************************
// ��������: SetStepBreakPoint
// ����˵��: ���õ��������ϵ㣬�����������call��reop������������������CC�ϵ㣬
//			 �������TF�ϵ�
// ��    ��: lracker
// ʱ    ��: 2019/10/27
// ��    ��: HANDLE hThread
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::SetStepBreakPoint(HANDLE hProcess, HANDLE hThread)
{
	// ��ȡ��ǰeipָ���λ���Ƿ�ָ�����call��rep
	// ���Ȼ�ȡeip
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ct);
	DWORD Addr = ct.Eip;
	// Ȼ���ȡEIPָ���λ�õĵ�һ���ֽ�
	PCHAR mnemonic;
	CHAR REP[4] = {};
	int nLen = 0;
	// ��ȡָ��ͳ���
	CCapstone::GetADisAsm(hProcess, (LPVOID)Addr, mnemonic, nLen);
	strncpy_s(REP, 4, mnemonic, 3);
	// �����callָ�����repָ��ĵĻ�
	if (!strcmp(mnemonic,"call")|| !strcmp(REP,"rep"))
	{
		// ����һ��ָ���λ������CC�ϵ㣬һ���Եģ�һ����Զ�ɾ���� 
		CBreakPoint::SetCCBreakPoint(hProcess, (LPVOID)(Addr + nLen), TRUE);
	}
	// ����͵�������ϵ�ͺ��ˣ�������Ϊtf�ϵ�
	else
	{
		CBreakPoint::SetTFBreakPoint(hThread);
	}
}

//******************************************************************************
// ��������: SetTFBreakPoint
// ����˵��: ���õ����ϵ�(TF�ϵ�)
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// ��    ��: HANDLE hThread
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::SetTFBreakPoint(HANDLE hThread)
{
	// ��ȡ�̻߳�����
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ct);
	// ��TF��־λ����Ϊ1
	ct.EFlags |= 0x100;	
	SetThreadContext(hThread, &ct);
}

//******************************************************************************
// ��������: SetCCBreakPoint
// ����˵��: ����һ������ϵ�,0xCC
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// ��    ��: HANDLE hProcess
// ��    ��: LPVOID Addr
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::SetCCBreakPoint(HANDLE hProcess, LPVOID Addr, BOOL Delete)
{
	// ��ָ����ַ�ĵ�һ���ֽ���д��0xCC
	// ��������ϵ���Ϣ�Ľṹ��
	BREAKPOINTINFO info = { Addr };
	// ��ȡ�õ�ַ�ĵ�һ���ֽڣ����ұ��浽�ṹ����
	ReadProcessMemory(hProcess, Addr, &info.old_opcode, 1, NULL);
	// ������д��0xCC
	WriteProcessMemory(hProcess, Addr, "\xCC", 1, NULL);
	// �������������öϵ�
	info.Delete = Delete;
	// �����õĶϵ㱣�浽������
	CBreakPoint::BreakPointList.push_back(info);
}

//******************************************************************************
// ��������: IsCondition
// ����˵��: �жϸöϵ�������Ƿ����
// ��    ��: lracker
// ʱ    ��: 2019/10/28
// ��    ��: HANDLE hThread
// ��    ��: LPVOID Addr
// �� �� ֵ: void
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
			// �ж�����һ���Ĵ���
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
			// �ж���ʲô������
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
// ��������: FixCCBreakPoint
// ����˵��: �޸�һ������ϵ㣬��ΪҪ��ԭ
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// ��    ��: HANDLE hProcess
// ��    ��: LPVOID Addr
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::FixCCBreakPoint(HANDLE hProcess, HANDLE hThread, LPVOID Addr)
{
	// �����ϵ��б�
	for (int i = 0; i < CBreakPoint::BreakPointList.size(); ++i)
	{
		if (CBreakPoint::BreakPointList[i].addr == Addr)
		{
			// 1. ��ȡ�Ĵ�����Ϣ���� eip - 1
			CONTEXT context = { CONTEXT_CONTROL };
			GetThreadContext(hThread, &context);
			context.Eip -= 1;
			SetThreadContext(hThread, &context);
			// ����ֻ���޸�һ��opcode���ѣ���û�дӶϵ��б���ɾ����
			WriteProcessMemory(hProcess, Addr, &CBreakPoint::BreakPointList[i].old_opcode, 1, NULL);
			// ���ñ�־����ʾ������Ҫ�������û�CC
			CBreakPoint::CCChange = TRUE;
			// �����Ҫɾ������ϵ�Ļ����Ǿʹ��б���ɾ����
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
// ��������: ResetCCBreakPoint
// ����˵��: �����ϵ��б���������ΪCC
// ��    ��: lracker
// ʱ    ��: 2019/10/26
// ��    ��: HANDLE hProcess
// ��    ��: LPVOID Addr
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::ResetCCBreakPoint(HANDLE hProcess)
{
	for (auto& i : BreakPointList)
	{
		WriteProcessMemory(hProcess, i.addr, "\xCC", 1, NULL);
	}
	// �ѱ�־�Ļ�������ʾ�Ѿ���������ΪCC��
	CBreakPoint::CCChange = FALSE;
}

//******************************************************************************
// ��������: SetHXBreakPoint
// ����˵��: ����һ��Ӳ���ϵ�
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// ��    ��: HANDLE hProcess
// ��    ��: HANDLE hThread
// ��    ��: LPVOID Addr
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::SetHWBreakPoint(HANDLE hThread, LPVOID Addr, CHAR Type, DWORD dwLen)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	// ��ȡ�̻߳�����
	GetThreadContext(hThread, &ct);
	// �������ִ�жϵ�Ļ�
	// ��ôҪ���ݳ��Ƚ��е�ַ����
	if (Type != 0)
	{ 
		dwLen--;
		// 1�ֽ�
		if (dwLen == 0)
		{
			Addr = Addr;
		}
		// 2�ֽڶ�������
		else if (dwLen == 1)	
		{
			Addr = (LPVOID)((DWORD)Addr - (DWORD)Addr % 2);
		}
		// 4�ֽڶ���
		else if (dwLen == 3)
		{
			Addr = (LPVOID)((DWORD)Addr - (DWORD)Addr % 4);
		}
		else
		{
			printf("��������ֻ��Ϊ1��2��4\n");
			return;
		}
	}
	PDBG_REG7 pDr7 = (PDBG_REG7)&ct.Dr7;
	// ����DR0û�б�ʹ��
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
		printf("û�п��е�Ӳ���ϵ�λ��!\n");
	}
	SetThreadContext(hThread, &ct);
}

//******************************************************************************
// ��������: FixHWBreakPoint
// ����˵��: �޸��ϵ�
// ��    ��: lracker
// ʱ    ��: 2019/10/26
// ��    ��: HANDLE hThread
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::FixHWBreakPoint(HANDLE hThread)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);
	// ��ȡ�� Dr7 �Ĵ�������������Щ�ϵ㱻ʹ��
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
// ��������: ResetHWBreakPoint
// ����˵��: ��������Ӳ���ϵ�
// ��    ��: lracker
// ʱ    ��: 2019/10/26
// ��    ��: HANDLE hThread
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::ResetHWBreakPoint(HANDLE hThread)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);
	// ��ȡ�� Dr7 �Ĵ�������������Щ�ϵ㱻ʹ��
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
// ��������: SetMemBreakPoint
// ����˵��: ����һ���ڴ�ִ�жϵ� 
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// ��    ��: HANDLE hProcess
// ��    ��: LPVOID Addr
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::SetMemBreakPoint(HANDLE hProcess, LPVOID Addr, DWORD64& MemAddr, DWORD& dwOldProtect, DWORD flNewProtect)
{
	// �ȱ���Ҫ�����ڴ�ϵ��λ��
	MemAddr = (DWORD64)Addr;
	// ��ȡ����ҳ�����ʼλ��
	DWORD64 StartAddr = (DWORD64)Addr & 0xFFFFF000;
	// ����ΪPAGE_NOACCESS
	VirtualProtectEx(hProcess, (LPVOID)StartAddr, 0x1000, flNewProtect, &dwOldProtect);
	return;
}
//******************************************************************************
// ��������: RecoverOpcode
// ����˵��: �ָ����е�CC�ϵ�opcode
// ��    ��: lracker
// ʱ    ��: 2019/10/27
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::RecoverOpcode(HANDLE hProcess)
{
	for (auto& i : CBreakPoint::BreakPointList)
	{
		
		WriteProcessMemory(hProcess, i.addr, &i.old_opcode, 1, NULL);
	}
}

//******************************************************************************
// ��������: RecoverCC
// ����˵��: ��������CC�ϵ�ΪCC
// ��    ��: lracker
// ʱ    ��: 2019/10/27
// ��    ��: HANDLE hProcess
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::RecoverCC(HANDLE hProcess, HANDLE hThread, LPVOID Addr)
{
	for (auto& i : CBreakPoint::BreakPointList)
	{
		// ����˿̲鿴�ĵط��պ���EIPָ���λ�ã�
		// Ҳ���Ǹպ�EIPָ���λ�øպ���CC�ϵ�
		// ��ô�Ͳ����޸���CC�ˣ���Ϊ��һ���ͻ��޸��ˡ�
		// ��������޸��˵Ļ��Ͳ����������ġ�
		// ��ȡ�̻߳�����
		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &ct);
		if (ct.Eip == (DWORD)i.addr)
			break;
		WriteProcessMemory(hProcess, i.addr, "\xCC", 1, NULL);
	}
	
}

//******************************************************************************
// ��������: ConditionCCBreakPoint
// ����˵��: ����һ�������ϵ�
// ��    ��: lracker
// ʱ    ��: 2019/10/28
// ��    ��: HANDLE hProcess
// ��    ��: LPVOID Addr
// ��    ��: string condition
// �� �� ֵ: void
//******************************************************************************
void CBreakPoint::ConditionCCBreakPoint(HANDLE hProcess, LPVOID Addr, PCHAR pReg, PCHAR pOperator,int nValue)
{
	// �����ж�һ���Ƿ��Ѿ�д����������ϵ���
	for (auto& i : CBreakPoint::BreakPointList)
	{
		if (i.addr == Addr)
		{
			// ����Ѿ�������ϵ��ˣ����������
			i.Reg = pReg;
			i.Operator = pOperator;
			i.nValue = nValue;
			return;
		}
	}
	// ��ָ����ַ�ĵ�һ���ֽ���д��0xCC
	// ��������ϵ���Ϣ�Ľṹ��
	BREAKPOINTINFO info = { Addr };
	info.Reg = pReg;
	info.Operator = pOperator;
	info.nValue = nValue;
	// ��ȡ�õ�ַ�ĵ�һ���ֽڣ����ұ��浽�ṹ����
	ReadProcessMemory(hProcess, Addr, &info.old_opcode, 1, NULL);
	// ������д��0xCC
	WriteProcessMemory(hProcess, Addr, "\xCC", 1, NULL);
	// �������������öϵ�
	info.Delete = FALSE;
	// �����õĶϵ㱣�浽������
	CBreakPoint::BreakPointList.push_back(info);
}

