#pragma once
#include "pch.h"

class RegistryManager
{
public:
	static HKEY CreateRegistryKey(HKEY hKeyRoot, LPCTSTR pszSubKey);
	static bool SetRegistryValue(HKEY hKey, LPCTSTR pszValue, DWORD dwType, PVOID pData, DWORD dwSize);
};