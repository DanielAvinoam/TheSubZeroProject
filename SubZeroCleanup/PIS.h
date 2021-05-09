#pragma once

#include <Windows.h>

struct UserPisParameters
{
	LPVOID loadLibraryA;
	LPVOID getProcAddress;
	int pid;
};

typedef HMODULE(WINAPI* pLoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef FARPROC(WINAPI* pGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef void(WINAPI* pSleep)(_In_ DWORD dwMilliseconds);
typedef HANDLE(WINAPI* pOpenProcess)(_In_ DWORD dwDesiredAccess, _In_ BOOL  bInheritHandle, _In_ DWORD dwProcessId);
typedef BOOL(WINAPI* pTerminateProcess)(_In_ HANDLE hProcess, _In_ UINT uExitCode);
typedef BOOL(WINAPI* pCloseHandle)(_In_ HANDLE hObject);
typedef BOOL(WINAPI* pDeleteFileA)(_In_ LPCSTR lpFileName);


#ifdef __cplusplus
extern "C" {
#endif

	DWORD WINAPI PisStart(struct UserPisParameters* pisParameters);

	void PisEnd();

#ifdef __cplusplus
}
#endif