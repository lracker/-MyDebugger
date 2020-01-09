#pragma once
#include <windows.h>
#include <vector>
#include <string>
using std::vector;
using std::string;

// 弄一个模块的结构体
// 保存模块的start地址
// end地址以及模块名
// 是否有符号，如果有符号的话
// 符号的地址

typedef struct _MODULE
{
	string ModuleName;
	DWORD64 ModuleStartAddr;
	DWORD64 ModuleEndAddr;
	string szExePath;
	BOOL IsSymbol;
	string SymbolPath;
}MyModule,*PMyModule;


typedef struct _PLGINFO
{
	HMODULE Base = 0;			// 加载基质
	char name[32] = { 0 };		// 插件的名称
} PLGINFO, * PPLGINFO;

extern HANDLE g_hProcess;


// 调试器类：建立调试子系统，处理接受到达到调试信息
// 获取用户的输入，并进行相应的输出反馈
class CDebugger
{
private:
	// 保存调试事件的结构体
	DEBUG_EVENT DebugEvent = { 0 };
	// 用于保存处理的结果
	DWORD dwCountinueStatus = DBG_CONTINUE;
	// 保存异常产生时对应的进程和线程句柄
	HANDLE ThreadHandle = NULL;
	HANDLE ProcessHandle = NULL;
	// 用于存放寄存器的信息
	vector<string> MyRegisterVector;
	// 用于存放栈的信息
	vector<string> MyStackVector;
	// 用来保存模块的信息
	vector<MyModule> MyModuleVector;
	// 保存插件的信息
	vector<PLGINFO> PluginsVector;
	// 用来保存内存断点的地址
	DWORD64 m_MemAddr = 0;
	// 保存之前的页面属性
	DWORD m_dwOldProtect;

public:
	// 接收一个路径，以调试的方式创建进程
	void Open(LPCSTR FilePath);
	// 接收并处理调试事件
	void Run();
	// 构造函数用来初始化和加载插件
	// CDebugger();
	void InitPlugin();
private:
	// 提供函数用于打开目标句柄
	void OpenHandles();
	// 提供函数用于关闭目标句柄
	void CloseHandles();
	// 用于处理接收到的所有异常事件
	void OnExceptionEvent();
	// 获取用户的输入
	void GetCommend();
	// 获取加载模块，并列出来
	BOOL GetModules();
	// 查看寄存器信息
	void GetRegister(HANDLE hThread, vector<string>& MyRegisterVector);
	// 获取栈的信息
	void GetStack(HANDLE hProcess, HANDLE hThread, vector<string>& MyStackerVector);
	// 用于查看内存信息
	void GetMemory(HANDLE hProcess, LPVOID Addr);
	// 用于修改内存信息
	void ChangeMemory(HANDLE hProcess, LPVOID Addr, vector<int> intvector);
	// 用于修改寄存器的值
	void ChangeRegister(HANDLE hThread, string Reg);
	// 获取该模块的导入表和导出表
	void GetTable(int i);
	// 获取帮助
	void GetHelp();
	// 修改汇编代码
	void ChangeAsm(int Addr);
	// DUMP
	void Dump();
};

