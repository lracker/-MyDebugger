#include "CCapstone.h"
#include "CBreakPoint.h"
#include "dbgHelp.h"
#include <tchar.h>
#include "CDebugger.h"

csh CCapstone::Handle = { 0 };
cs_opt_mem CCapstone::OptMem = { 0 };
//******************************************************************************
// ��������: Init
// ����˵��: ���ڳ�ʼ���ĺ���
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// �� �� ֵ: void
//******************************************************************************
void CCapstone::Init()
{
	// ���öѿռ�Ļص�����
	OptMem.free = free;
	OptMem.calloc = calloc;
	OptMem.malloc = malloc;
	OptMem.realloc = realloc;
	OptMem.vsnprintf = (cs_vsnprintf_t)vsprintf_s;
	// ע��ѿռ�����麯��
	cs_option(NULL, CS_OPT_MEM, (size_t)&OptMem);
	// ��һ�����
	cs_open(CS_ARCH_X86, CS_MODE_32, &CCapstone::Handle);
}

//******************************************************************************
// ��������: DisAsm
// ����˵��: ����ִ�з����ĺ���
// ��    ��: lracker
// ʱ    ��: 2019/10/25
// ��    ��: HANDLE Handle
// ��    ��: LPVOID Addr
// ��    ��: DWORD dwCount
// �� �� ֵ: void
//******************************************************************************
void CCapstone::DisAsm(HANDLE hProcess, LPVOID Addr, DWORD dwCount)
{
	// ������ȡָ��λ���ڴ�Ļ�������Ϣ
	cs_insn* ins = nullptr;
	PCHAR buff = new CHAR[dwCount * 16]();
	// ��ȡָ�����ȵ��ڴ�ռ�
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
		}// �����Ӧ�ķ����
		printf("\t%s  %s\t", ins[i].mnemonic, ins[i].op_str);
		// �����ȡ������callָ��
		printf("\n");
	}
	printf("\n");
	// �ͷŶ�̬����Ŀռ�
	delete[] buff;
	cs_free(ins, nCount);
}



//******************************************************************************
// ��������: GetADisAsm
// ����˵��: ��ȡһ��ָ��ͳ���
// ��    ��: lracker
// ʱ    ��: 2019/10/27
// ��    ��: HANDLE hProcess
// ��    ��: LPVOID Addr
// ��    ��: PCHAR & mnemonic
// ��    ��: int & nLen
// �� �� ֵ: void
//******************************************************************************
void CCapstone::GetADisAsm(HANDLE hProcess, LPVOID Addr, PCHAR& mnemonic, int& nLen)
{
	cs_insn* ins = nullptr;
	PCHAR Buffer[16] = { 0 };
	ReadProcessMemory(hProcess, Addr, Buffer, 16, NULL);
	cs_disasm(CCapstone::Handle, (uint8_t*)Buffer, 16, (uint64_t)Addr, 0, &ins);
	// ��ȡָ��
	mnemonic = ins->mnemonic;
	// ��ȡ����
	nLen = ins->size;
}

//******************************************************************************
// ��������: GetFunName
// ����˵��: ���ݺ�����ַ��ȡ������
// ��    ��: lracker
// ʱ    ��: 2019/10/30
// ��    ��: int nAddr
// �� �� ֵ: string
//******************************************************************************
string CCapstone::GetFunName(DWORD64 nAddr)
{
	DWORD64 dwDisplacement = 0;
	char Buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)] = {};
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)Buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	// ���ݵ�ַ��ȡ������Ϣ
	if (!SymFromAddr(g_hProcess, nAddr, 0, pSymbol))
		return "NULL";
	return pSymbol->Name;
}

