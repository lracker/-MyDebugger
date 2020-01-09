#pragma once
#include <windows.h>
#include <vector>
#include <string>
using std::vector;
using std::string;

// Ūһ��ģ��Ľṹ��
// ����ģ���start��ַ
// end��ַ�Լ�ģ����
// �Ƿ��з��ţ�����з��ŵĻ�
// ���ŵĵ�ַ

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
	HMODULE Base = 0;			// ���ػ���
	char name[32] = { 0 };		// ���������
} PLGINFO, * PPLGINFO;

extern HANDLE g_hProcess;


// �������ࣺ����������ϵͳ��������ܵ��ﵽ������Ϣ
// ��ȡ�û������룬��������Ӧ���������
class CDebugger
{
private:
	// ��������¼��Ľṹ��
	DEBUG_EVENT DebugEvent = { 0 };
	// ���ڱ��洦��Ľ��
	DWORD dwCountinueStatus = DBG_CONTINUE;
	// �����쳣����ʱ��Ӧ�Ľ��̺��߳̾��
	HANDLE ThreadHandle = NULL;
	HANDLE ProcessHandle = NULL;
	// ���ڴ�żĴ�������Ϣ
	vector<string> MyRegisterVector;
	// ���ڴ��ջ����Ϣ
	vector<string> MyStackVector;
	// ��������ģ�����Ϣ
	vector<MyModule> MyModuleVector;
	// ����������Ϣ
	vector<PLGINFO> PluginsVector;
	// ���������ڴ�ϵ�ĵ�ַ
	DWORD64 m_MemAddr = 0;
	// ����֮ǰ��ҳ������
	DWORD m_dwOldProtect;

public:
	// ����һ��·�����Ե��Եķ�ʽ��������
	void Open(LPCSTR FilePath);
	// ���ղ���������¼�
	void Run();
	// ���캯��������ʼ���ͼ��ز��
	// CDebugger();
	void InitPlugin();
private:
	// �ṩ�������ڴ�Ŀ����
	void OpenHandles();
	// �ṩ�������ڹر�Ŀ����
	void CloseHandles();
	// ���ڴ�����յ��������쳣�¼�
	void OnExceptionEvent();
	// ��ȡ�û�������
	void GetCommend();
	// ��ȡ����ģ�飬���г���
	BOOL GetModules();
	// �鿴�Ĵ�����Ϣ
	void GetRegister(HANDLE hThread, vector<string>& MyRegisterVector);
	// ��ȡջ����Ϣ
	void GetStack(HANDLE hProcess, HANDLE hThread, vector<string>& MyStackerVector);
	// ���ڲ鿴�ڴ���Ϣ
	void GetMemory(HANDLE hProcess, LPVOID Addr);
	// �����޸��ڴ���Ϣ
	void ChangeMemory(HANDLE hProcess, LPVOID Addr, vector<int> intvector);
	// �����޸ļĴ�����ֵ
	void ChangeRegister(HANDLE hThread, string Reg);
	// ��ȡ��ģ��ĵ����͵�����
	void GetTable(int i);
	// ��ȡ����
	void GetHelp();
	// �޸Ļ�����
	void ChangeAsm(int Addr);
	// DUMP
	void Dump();
};

