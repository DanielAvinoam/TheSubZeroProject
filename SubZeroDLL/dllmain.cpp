// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "synchapi.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(nullptr, "SubZero DllMain Invoked", "SubZero", 0);
        //SetThreadExecutionState(ES_AWAYMODE_REQUIRED);
        //Sleep(30000);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}