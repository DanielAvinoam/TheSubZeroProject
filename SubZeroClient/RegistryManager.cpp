#include "pch.h"
#include "RegistryManager.h"

HKEY RegistryManager::CreateRegistryKey(HKEY hKeyRoot, LPCTSTR pszSubKey) {
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

bool RegistryManager::SetRegistryValue(HKEY hKey, LPCTSTR pszValue, DWORD dwType, PVOID pData, DWORD dwSize) {
	LONG lRes = 0;
	lRes = RegSetValueEx(hKey, pszValue, 0, dwType, (unsigned char*)pData, dwSize);

	if (lRes != ERROR_SUCCESS) {
		::SetLastError(lRes);
		return false;
	}
	return true;
}