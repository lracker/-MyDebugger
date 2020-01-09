#pragma once
#include <windows.h>
#include <vector>
#include <string>
using std::vector;
using std::string;

// 保存断点信息的结构体
typedef struct _BREAKPOINTINFO
{
	LPVOID addr = 0;	 // 地址
	BYTE old_opcode = 0; // 旧的OPCODE
	BOOL Delete = FALSE; // 是否是一次性断点
	string Reg = "";	 // 条件断点下要求的寄存器
	string Operator = "";// 符号
	int nValue = 0;		 // 条件断点下的值
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
// 一个断点类
class CBreakPoint
{
private:

	// 保存了刚才碰到了哪一个断点
	static int nDR6;
public:
	static BOOL CCChange;
	static BOOL HWChange;
	// 判断是否因为内存断点引起的单步
	static BOOL MemChange;
	// 维护一个断点列表，保存所有的断点信息
	static vector<BREAKPOINTINFO> BreakPointList;
	// 设置单步步过断点
	static void SetStepBreakPoint(HANDLE hProcess, HANDLE hThread);
	// 设置单步断点(TF断点)
	static void SetTFBreakPoint(HANDLE hThread);
	// 设置一个软件断点(CC断点)
	static void SetCCBreakPoint(HANDLE hProcess, LPVOID Addr, BOOL Delete);
	// 判断该断点的条件是否成立
	static BOOL IsCondition(HANDLE hThread, LPVOID Addr);
	// 修复一个软件断点(CC断点)的反汇编代码
	static void FixCCBreakPoint(HANDLE hProcess, HANDLE hThread, LPVOID Addr);
	// 遍历断点列表并重新设置为CC
	static void ResetCCBreakPoint(HANDLE hProcess);
	// 设置一个硬件断点
	static void SetHWBreakPoint(HANDLE hThread, LPVOID Addr, CHAR Type, DWORD dwLen);
	// 修复一个硬件断点
	static void FixHWBreakPoint(HANDLE hThread);
	// 重新设置一个硬件断点
	static void ResetHWBreakPoint(HANDLE hThread);
	// 设置一个内存断点 
	static void SetMemBreakPoint(HANDLE hProcess, LPVOID Addr, DWORD64& MemAddr, DWORD& dwOldProtect, DWORD flNewProtect);
	// 恢复所有的断点opcode
	static void RecoverOpcode(HANDLE hProcess);
	// 设置所有CC断点为CC
	static void RecoverCC(HANDLE hProcess, HANDLE hThread, LPVOID Addr);
	// 设置一个条件断点
	static void ConditionCCBreakPoint(HANDLE hProcess, LPVOID Addr, PCHAR pReg, PCHAR pOperator, int nValue);
};

