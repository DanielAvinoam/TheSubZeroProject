#include "pch.h"
#include "HttpClient.h"

constexpr DWORD SecondsBetweenFetches = 5;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    HANDLE hThread;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //::MessageBoxA(nullptr, "SubZero DllMain Invoked", "SubZero", 0);

        //HttpClient::FetchFromServerLoop((LPVOID)&SecondsBetweenFetches);

        hThread = ::CreateThread(
            nullptr,                          // default security attributes
            0,                                // use default stack size  
            HttpClient::FetchFromServerLoop,  // thread function name
            (LPVOID)&SecondsBetweenFetches,   // argument to thread function 
            0,                                // use default creation flags 
            nullptr);                 // returns the thread identifier 

        if (!hThread)
        {
            // Thread creation failed.
            // More details can be retrieved by calling GetLastError()
            return FALSE;
        }

        ::SleepEx(INFINITE, FALSE);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}