#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "Capstone/include/capstone.h"
#pragma comment(lib,"capstone/capstone.lib")
#pragma comment(linker,"/NODEFAULTLIB:\"libcmtd.lib\"")
using std::vector;
using std::string;

// ���������(������)����Ҫ������ͨ������ĵ�ַ����
// ������汣��Ĵ�����Ϣ�����Զ������ʽ���зḻ��

class CCapstone
{
private:
	// ���ڳ�ʼ�����ڴ����ľ��
	static csh Handle;
	static cs_opt_mem OptMem;

public:
	// ����ΪĬ�Ϲ��캯��
	CCapstone() = default;
	~CCapstone() = default;
	// ���ڳ�ʼ���ĺ���
	static void Init();
	// ����ִ�з����ĺ���
	static void DisAsm(HANDLE hProcess, LPVOID Addr, DWORD dwCount);
	// ��ȡһ��ָ��ͳ���
	static void GetADisAsm(HANDLE hProcess, LPVOID Addr, PCHAR& mnemonic, int& nLen);
	static string GetFunName(DWORD64 nAddr);
};

