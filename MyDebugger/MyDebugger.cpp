// MyDebugger.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "CDebugger.h"
#include <TlHelp32.h>
#include "CCapstone.h"

//******************************************************************************
// 函数名称: GetAllProcess
// 函数说明: 获取所有进程的
// 作    者: lracker
// 时    间: 2019/10/28
// 返 回 值: void
//******************************************************************************
void GetAllProcess()
{
	printf("进程名     PID\n");
	HANDLE hSpap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	if (!Process32First(hSpap, &pe))
		return;
	do 
	{
		printf("%S\t%d\n", pe.szExeFile, pe.th32ProcessID);
	} while (Process32Next(hSpap, &pe));
}

int main()
{
	while (true)
	{
		CDebugger MyDebugger;
		MyDebugger.InitPlugin();
		printf("1.创建调试进程\n");
		printf("2.附加活动进程\n");  
		int input = 0;
		scanf_s("%d", &input);
		if (input == 1)
		{
			printf("请输入调试进程的路径:\n");
			char Path[MAX_PATH] = { 0 };
			scanf_s("%s", Path, MAX_PATH);
			MyDebugger.Open(Path);
			system("cls");
			MyDebugger.Run();
		}
		// 附加进程
		else if (input == 2)
		{
			// 首先获取这个所有进程
			GetAllProcess();
			printf("请输入附加进程的PID\n");
			DWORD dwPid = 0;
			scanf_s("%d", &dwPid);
			DebugActiveProcess(dwPid);
			// 初始化反汇编引擎
			CCapstone::Init();
			system("cls");
			MyDebugger.Run();
		}
		else
		{
			printf("请重新输入\n");
		}
	}
}

