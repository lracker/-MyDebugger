#include "CCapstone.h"
#include "CBreakPoint.h"
#include "dbgHelp.h"
#include <tchar.h>
#include "CDebugger.h"

csh CCapstone::Handle = { 0 };
cs_opt_mem CCapstone::OptMem = { 0 };
//******************************************************************************
// 函数名称: Init
// 函数说明: 用于初始化的函数
// 作    者: lracker
// 时    间: 2019/10/25
// 返 回 值: void
//******************************************************************************
void CCapstone::Init()
{
	// 配置堆空间的回调函数
	OptMem.free = free;
	OptMem.calloc = calloc;
	OptMem.malloc = malloc;
	OptMem.realloc = realloc;
	OptMem.vsnprintf = (cs_vsnprintf_t)vsprintf_s;
	// 注册堆空间管理组函数
	cs_option(NULL, CS_OPT_MEM, (size_t)&OptMem);
	// 打开一个句柄
	cs_open(CS_ARCH_X86, CS_MODE_32, &CCapstone::Handle);
}

//******************************************************************************
// 函数名称: DisAsm
// 函数说明: 用于执行反汇编的函数
// 作    者: lracker
// 时    间: 2019/10/25
// 参    数: HANDLE Handle
// 参    数: LPVOID Addr
// 参    数: DWORD dwCount
// 返 回 值: void
//******************************************************************************
void CCapstone::DisAsm(HANDLE hProcess, LPVOID Addr, DWORD dwCount)
{
	// 用来读取指令位置内存的缓冲区信息
	cs_insn* ins = nullptr;
	PCHAR buff = new CHAR[dwCount * 16]();
	// 读取指定长度的内存空间
	DWORD dwWrite = 0;
	ReadProcessMemory(hProcess, (LPVOID)Addr, buff, dwCount * 16, &dwWrite);
	int nCount = cs_disasm(CCapstone::Handle, (uint8_t*)buff, dwCount * 16, (uint64_t)Addr, 0, &ins);
	for (DWORD i = 0; i< nCount && i<dwCount; ++i)
	{
		printf("%08X\t", (UINT)ins[i].address);
		for (uint16_t j = 0; j < 16; ++j)
		{
			if (j < ins[i].size)
				printf("%02X", ins[i].bytes[j]);
			else
				printf("  ");
		}// 输出对应的反汇编
		printf("\t%s  %s\t", ins[i].mnemonic, ins[i].op_str);
		// 如果截取到的是call指令
		printf("\n");
	}
	printf("\n");
	// 释放动态分配的空间
	delete[] buff;
	cs_free(ins, nCount);
}



//******************************************************************************
// 函数名称: GetADisAsm
// 函数说明: 获取一条指令和长度
// 作    者: lracker
// 时    间: 2019/10/27
// 参    数: HANDLE hProcess
// 参    数: LPVOID Addr
// 参    数: PCHAR & mnemonic
// 参    数: int & nLen
// 返 回 值: void
//******************************************************************************
void CCapstone::GetADisAsm(HANDLE hProcess, LPVOID Addr, PCHAR& mnemonic, int& nLen)
{
	cs_insn* ins = nullptr;
	PCHAR Buffer[16] = { 0 };
	ReadProcessMemory(hProcess, Addr, Buffer, 16, NULL);
	cs_disasm(CCapstone::Handle, (uint8_t*)Buffer, 16, (uint64_t)Addr, 0, &ins);
	// 获取指令
	mnemonic = ins->mnemonic;
	// 获取长度
	nLen = ins->size;
}

//******************************************************************************
// 函数名称: GetFunName
// 函数说明: 根据函数地址获取函数名
// 作    者: lracker
// 时    间: 2019/10/30
// 参    数: int nAddr
// 返 回 值: string
//******************************************************************************
string CCapstone::GetFunName(DWORD64 nAddr)
{
	DWORD64 dwDisplacement = 0;
	char Buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)] = {};
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)Buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	// 根据地址获取符号信息
	if (!SymFromAddr(g_hProcess, nAddr, 0, pSymbol))
		return "NULL";
	return pSymbol->Name;
}

