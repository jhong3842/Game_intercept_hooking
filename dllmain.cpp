// dllmain.cpp : DLL 응용 프로그램의 진입점을 정의합니다.
#include "stdafx.h"

#define target_process "ac_client.exe"
#define hook_offset  0x65fc4

//함수 포인터 type 정의
typedef void (*unkill)(void);
#define _MY_DEBUG 1


EXTERN_C __declspec(dllimport) void hook();
EXTERN_C __declspec(dllimport) HANDLE GetHandletoName();
EXTERN_C __declspec(dllexport) void Cheat_Key();
EXTERN_C __declspec(dllexport) void unkilled();
EXTERN_C __declspec(dllimport) void Error(char* error);
EXTERN_C __declspec(dllimport) void myOutputDebugString(LPCTSTR pszStr, ...);
EXTERN_C __declspec(dllimport) void EnableDebugPriv();
EXTERN_C __declspec(dllimport) char* WchartoChar(const wchar_t *pwstrSrc);



/////////////////////////////


//0x50f4f4 --> 0xe8a08d02[028]

char* gOffset = (char*)0x50f4f4;


typedef struct user_info{
	char unknown[247];
	int HP;
	int Armor;
}USER,*PUSER;





char* WchartoChar(wchar_t *pwstrSrc){
	int nlen = wcslen(pwstrSrc);
	char *pstr = (char*)malloc(sizeof(char) * nlen + 1);
	wcstombs(pstr, pwstrSrc, nlen + 1);
	return pstr;
}

void myOutputDebugString(LPCTSTR pszStr, ...)
{
#ifdef _MY_DEBUG   
	TCHAR szMsg[256];
	va_list args;
	va_start(args, pszStr);
	_vstprintf_s(szMsg, 256, pszStr, args);
	OutputDebugString(szMsg);
#endif   
}

void hook(){

	//Game Base Address Get
	char* baseaddr = (char*)GetModuleHandle(_T(target_process));

	//실패
	if (!baseaddr) MessageBoxA(NULL, "Error", "Error", MB_OK);
	//성공	
	else MessageBoxA(NULL, "Injected","Success" , MB_OK);
	
	//변조 할 Addr Get
	char* target_Addr = baseaddr + hook_offset;
	DWORD dwoldState = NULL;

	//함수 쓰기 권한 줌
	if (!VirtualProtect(
		(LPVOID)target_Addr,//Address
		5, //size
		PAGE_EXECUTE_READWRITE, // Change state
		&dwoldState)//save Old state
		)
		{
			MessageBoxA(NULL, "Fail", "Fail VirtualProtected", MB_OK);
			return;
		}

	myOutputDebugString(_T("target_Addr = %08x\n"), target_Addr);

	//Export Function Address Get
	//의문점 왜 GetModuleHandle(NULL, FUNC NAME)하면 안대지?
	HMODULE hdll = GetModuleHandle(_T("ConsoleApplication2.dll"));
	if (!hdll){
		MessageBoxA(NULL, "Fail", "Fail GetModuleHandle", MB_OK);
	}
	myOutputDebugString(_T("HDLL = %08x\n"), hdll);

	//함수 주소 가져오기
	unkill Func_Addr = (unkill)GetProcAddress
		(hdll,				//현재 DLL HANDLE
		(LPCSTR)"Cheat_Key");//FUNCTION NAME
	myOutputDebugString(_T("Func_Addr = %08x\n"), Func_Addr);
	if (!Func_Addr) MessageBoxA(NULL, "Fail", "GetProcAddress", MB_OK);
	


	//target process Handle Get
	HANDLE proc_Handle = GetHandletoName();
	if (proc_Handle) MessageBoxA(NULL, "Fail", "GetHandletoName", MB_OK);
	
	myOutputDebugString(_T("proc_Handle = %08x\n"), proc_Handle);

	SIZE_T nSize;
	// E8 [called - calling - 5[strlength]]

	DWORD dwOperand = (DWORD)Func_Addr - (DWORD)target_Addr - 5;
	

	//little endian 으로 넣어줌
	unsigned char write_buf[5];
	write_buf[0] = '\xe8';
	write_buf[1] = *((unsigned char*)&dwOperand);
	write_buf[2] = *((unsigned char*)&dwOperand + 1);
	write_buf[3] = *((unsigned char*)&dwOperand + 2);
	write_buf[4] = *((unsigned char*)&dwOperand + 3);
	myOutputDebugString(_T("CALL OPERAND= %10x\n"), write_buf);
	
	if(WriteProcessMemory(
		(LPVOID)proc_Handle,
		(LPVOID)target_Addr,
		write_buf,
		5,
		&nSize)) MessageBoxA(NULL, "Success", "WriteMem", MB_OK);
	
}



HANDLE GetHandletoName()
{
	EnableDebugPriv();
	HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hPID, &ProcEntry);
	do
	{ 
		myOutputDebugString(_T("process name = %s\n"), (char*)ProcEntry.szExeFile);
		char* szExe = WchartoChar(ProcEntry.szExeFile);
		if (strcmp(szExe, "ac_client.exe") == 0)
		{
			myOutputDebugString(_T("Come in?"));
			DWORD dwPID = ProcEntry.th32ProcessID;
			
			CloseHandle(hPID);
			
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
			
			return hProcess;
		}
	}
	while (Process32Next(hPID, &ProcEntry));
}

void EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

	CloseHandle(hToken);
}

void unkilled(){

	PUSER user = (PUSER)*(DWORD*)gOffset;

	while (1){
		user->HP = 300;
		user->Armor = 400;
	}
	
}

void Cheat_Key(){
	char* buf;
	char len;
	_asm{
		mov buf, esi; //pointer value
		mov len, bl;
		pushad;
	}
	//strcpy(buf, "12345");
	buf[len - 1] ='\x00';
	
	if (!strcmp("unkilled", buf)){
		CreateThread(NULL,
			NULL,
			(LPTHREAD_START_ROUTINE)&unkilled,
			NULL,
			NULL,
			NULL);
	}
	
	_asm{
		popad;
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hook();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

