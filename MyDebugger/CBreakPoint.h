#pragma once
#include <windows.h>
#include <vector>
#include <string>
using std::vector;
using std::string;

// ����ϵ���Ϣ�Ľṹ��
typedef struct _BREAKPOINTINFO
{
	LPVOID addr = 0;	 // ��ַ
	BYTE old_opcode = 0; // �ɵ�OPCODE
	BOOL Delete = FALSE; // �Ƿ���һ���Զϵ�
	string Reg = "";	 // �����ϵ���Ҫ��ļĴ���
	string Operator = "";// ����
	int nValue = 0;		 // �����ϵ��µ�ֵ
} BREAKPOINTINFO, * PBREAKPOINTINFO;
typedef struct _DBG_REG7
{
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned Reserve1 : 3;
	unsigned GD : 1;
	unsigned Reverse2 : 2;
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
}DBG_REG7, * PDBG_REG7;
// һ���ϵ���
class CBreakPoint
{
private:

	// �����˸ղ���������һ���ϵ�
	static int nDR6;
public:
	static BOOL CCChange;
	static BOOL HWChange;
	// �ж��Ƿ���Ϊ�ڴ�ϵ�����ĵ���
	static BOOL MemChange;
	// ά��һ���ϵ��б��������еĶϵ���Ϣ
	static vector<BREAKPOINTINFO> BreakPointList;
	// ���õ��������ϵ�
	static void SetStepBreakPoint(HANDLE hProcess, HANDLE hThread);
	// ���õ����ϵ�(TF�ϵ�)
	static void SetTFBreakPoint(HANDLE hThread);
	// ����һ������ϵ�(CC�ϵ�)
	static void SetCCBreakPoint(HANDLE hProcess, LPVOID Addr, BOOL Delete);
	// �жϸöϵ�������Ƿ����
	static BOOL IsCondition(HANDLE hThread, LPVOID Addr);
	// �޸�һ������ϵ�(CC�ϵ�)�ķ�������
	static void FixCCBreakPoint(HANDLE hProcess, HANDLE hThread, LPVOID Addr);
	// �����ϵ��б���������ΪCC
	static void ResetCCBreakPoint(HANDLE hProcess);
	// ����һ��Ӳ���ϵ�
	static void SetHWBreakPoint(HANDLE hThread, LPVOID Addr, CHAR Type, DWORD dwLen);
	// �޸�һ��Ӳ���ϵ�
	static void FixHWBreakPoint(HANDLE hThread);
	// ��������һ��Ӳ���ϵ�
	static void ResetHWBreakPoint(HANDLE hThread);
	// ����һ���ڴ�ϵ� 
	static void SetMemBreakPoint(HANDLE hProcess, LPVOID Addr, DWORD64& MemAddr, DWORD& dwOldProtect, DWORD flNewProtect);
	// �ָ����еĶϵ�opcode
	static void RecoverOpcode(HANDLE hProcess);
	// ��������CC�ϵ�ΪCC
	static void RecoverCC(HANDLE hProcess, HANDLE hThread, LPVOID Addr);
	// ����һ�������ϵ�
	static void ConditionCCBreakPoint(HANDLE hProcess, LPVOID Addr, PCHAR pReg, PCHAR pOperator, int nValue);
};

