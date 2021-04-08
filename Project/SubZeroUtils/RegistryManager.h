#pragma once
#include "pch.h"
#include "Win32ErrorCodeException.h"

class RegistryManager
{
public:
	virtual ~RegistryManager() = default;
	
	// Delete copy constructor, assignment operator, move constructor, move operator:
	RegistryManager& operator=(const RegistryManager&) = delete;
	RegistryManager(const RegistryManager&) = delete;
	RegistryManager(RegistryManager&&) = delete;
	RegistryManager& operator=(RegistryManager&&) = delete;
	
	static HKEY OpenRegistryKey(HKEY hKeyRoot, const std::wstring wsSubKey);
	
	static HKEY CreateRegistryKey(HKEY hKeyRoot, const std::wstring wsSubKey);
	
	static void DeleteRegistryKey(HKEY hKeyRoot, const std::wstring wsSubKey);
	
	static void SetRegistryValue(HKEY hKey, const std::wstring wsValue, DWORD dwType, PVOID pData, DWORD dwSize);
	
	static void DeleteRegistryValue(HKEY hKey, const std::wstring wsValue);
};