#include "pch.h"
#include "MinHook.h"
#include "WinSock2.h"
#include "hook.h"
#include <iostream>
#include <fstream>
#include <string>
#pragma comment(lib, "libMinHook.x64.lib")
using namespace std;

decltype(&send) pOriginSend = nullptr;
decltype(&recv) pOriginRecv = nullptr;
SendCallBack pSendCallBack = nullptr;
RecvCallBack pRecvCallBack = nullptr;

void InitLog()
{
#ifdef DEBUG
	ofstream logFile("hook.log", ios::out);
#endif
}

void Log(const string& msg)
{
#ifdef DEBUG
	ofstream logFile("hook.log", ios::app);
	if (logFile.is_open())
	{
		SYSTEMTIME st;
		GetLocalTime(&st);
		logFile << "[" << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] " << msg << endl;
		logFile.close();
	}
#endif
}

int WINAPI MySend(SOCKET s, PCHAR buf, int len, int flags)
{
	return pSendCallBack(s, buf, len);
}

int WINAPI MyRecv(SOCKET s, PCHAR buf, int len, int flags)
{
	int res = pOriginRecv(s, buf, len, flags);
	if (res > 0)
	{
		pRecvCallBack(s, buf, res);
	}
	return res;
}

int WINAPI Send(SOCKET s, PCHAR buf, int len)
{
	return pOriginSend(s, buf, len, 0);
}

void SetSendCallBack(SendCallBack pCallBack) {
	pSendCallBack = pCallBack;
}

void SetRecvCallBack(RecvCallBack pCallBack) {
	pRecvCallBack = pCallBack;
}

void EnableHook()
{
	InitLog();
	MH_STATUS status = MH_Initialize();
	if (status != MH_OK)
	{
		Log("MinHook 初始化失败");
		return;
	}
	Log("MinHook 初始化成功");

	status = MH_CreateHookApi(L"ws2_32.dll", "send", reinterpret_cast<LPVOID>(MySend), reinterpret_cast<LPVOID*>(&pOriginSend));
	if (status != MH_OK)
	{
		Log("创建 send Hook 失败");
	}

	status = MH_CreateHookApi(L"ws2_32.dll", "recv", reinterpret_cast<LPVOID>(MyRecv), reinterpret_cast<LPVOID*>(&pOriginRecv));
	if (status != MH_OK)
	{
		Log("创建 recv Hook 失败");
	}

	status = MH_EnableHook(MH_ALL_HOOKS);
	if (status != MH_OK)
	{
		Log("开启 Hook 失败");
	}
	else
	{
		Log("开启 Hook 成功");
	}
}

void DisableHook()
{
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();
}
