#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "Capstone/include/capstone.h"
#pragma comment(lib,"capstone/capstone.lib")
#pragma comment(linker,"/NODEFAULTLIB:\"libcmtd.lib\"")
using std::vector;
using std::string;

// 反汇编引擎(工具类)：主要操作是通过传入的地址返回
// 变出上面保存的代码信息，可以对输出格式进行丰富化

class CCapstone
{
private:
	// 用于初始化和内存管理的句柄
	static csh Handle;
	static cs_opt_mem OptMem;

public:
	// 设置为默认构造函数
	CCapstone() = default;
	~CCapstone() = default;
	// 用于初始化的函数
	static void Init();
	// 用于执行反汇编的函数
	static void DisAsm(HANDLE hProcess, LPVOID Addr, DWORD dwCount);
	// 获取一条指令和长度
	static void GetADisAsm(HANDLE hProcess, LPVOID Addr, PCHAR& mnemonic, int& nLen);
	static string GetFunName(DWORD64 nAddr);
};

