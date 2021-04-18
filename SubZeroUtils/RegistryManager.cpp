#include "RegistryManager.h"
#include "Win32ErrorCodeException.h"

HKEY RegistryManager::OpenRegistryKey(HKEY hKeyRoot, const std::wstring wsSubKey) {
	HKEY hkResult = nullptr;	
	
	if (ERROR_SUCCESS != ::RegOpenKeyExW(hKeyRoot, wsSubKey.c_str(), 0, KEY_ALL_ACCESS, &hkResult))
		throw Win32ErrorCodeException("Could not open registry key");
	
	return hkResult;
}

HKEY RegistryManager::CreateRegistryKey(HKEY hKeyRoot, const std::wstring wsSubKey) {
	HKEY hKey = nullptr;
	PACL pACL = nullptr;
	DWORD dwFunc = 0;
	LONG  lRes;
	SECURITY_ATTRIBUTES SA;
	SECURITY_DESCRIPTOR SD;


	if (!::InitializeSecurityDescriptor(&SD, SECURITY_DESCRIPTOR_REVISION))
		throw Win32ErrorCodeException("Error initializing security descriptor");

	if (!::SetSecurityDescriptorDacl(&SD, TRUE, pACL, FALSE))
		throw Win32ErrorCodeException("Error setting security descriptor's DACL");

	SA.nLength = sizeof(SA);
	SA.lpSecurityDescriptor = &SD;
	SA.bInheritHandle = FALSE;

	lRes = ::RegCreateKeyExW(
		hKeyRoot,
		wsSubKey.c_str(),
		0,
		nullptr,
		REG_OPTION_NON_VOLATILE,
		KEY_WRITE,
		&SA,
		&hKey,
		&dwFunc
	);

	if (lRes) 
		throw Win32ErrorCodeException("Error creating registry key");
	
	return hKey;
}

void RegistryManager::SetRegistryValue(HKEY hKey, const std::wstring wsValue, DWORD dwType, PVOID pData, DWORD dwSize) {
	
	if (hKey == INVALID_HANDLE_VALUE)
		throw Win32ErrorCodeException("Invalid registry key handle");
	
	if (::RegSetValueExW(hKey, wsValue.c_str(), 0, dwType, (UCHAR*)pData, dwSize) != ERROR_SUCCESS)
		throw Win32ErrorCodeException("Could not set registry key value");		
}

void RegistryManager::DeleteRegistryKey(HKEY hKeyRoot, const std::wstring wsSubKey) {
	if (::RegDeleteKeyW(hKeyRoot, wsSubKey.c_str()) != ERROR_SUCCESS)
		throw Win32ErrorCodeException("Could not delete registry key");
}

void RegistryManager::DeleteRegistryValue(HKEY hKey, const std::wstring wsValue) {
	if(::RegDeleteValueW(hKey, wsValue.c_str()) != ERROR_SUCCESS)
		throw Win32ErrorCodeException("Could not delete registry value");
}
