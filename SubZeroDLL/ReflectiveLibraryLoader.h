#pragma once
#include "pch.h"

typedef void* HMEMORYMODULE;

typedef void* HMEMORYRSRC;

typedef HMODULE HCUSTOMMODULE;

struct ExportNameEntry {
    LPCSTR name;
    WORD idx;
};

typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef int (WINAPI* ExeEntryProc)(void);

#ifdef _WIN64
typedef struct POINTER_LIST {
    struct POINTER_LIST* next;
    void* address;
} POINTER_LIST;
#endif

typedef struct {
    PIMAGE_NT_HEADERS headers;
    unsigned char* codeBase;
    HCUSTOMMODULE* modules;
    int numModules;
    BOOL initialized;
    BOOL isDLL;
    BOOL isRelocated;
    struct ExportNameEntry* nameExportsTable;
    void* userdata;
    ExeEntryProc exeEntry;
    DWORD pageSize;
#ifdef _WIN64
    POINTER_LIST* blockedMemory;
#endif
} MEMORYMODULE, * PMEMORYMODULE;

typedef struct {
    LPVOID address;
    LPVOID alignedAddress;
    SIZE_T size;
    DWORD characteristics;
    BOOL last;
} SECTIONFINALIZEDATA, * PSECTIONFINALIZEDATA;


class ReflectiveLibraryLoader
{
	static HMEMORYMODULE MemoryLoadLibrary(const void*, size_t);

	void MemoryFreeLibrary(HMEMORYMODULE);
};

