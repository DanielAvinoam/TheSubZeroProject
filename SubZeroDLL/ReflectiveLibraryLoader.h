#pragma once
#include "pch.h"

#define DOS_HEADER_OFFSET 0x3C /* e_lfanew Offset */ + sizeof(DWORD) /* e_lfanew Size*/

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

#define GET_HEADER_DICTIONARY(Module, idx)  &(Module)->headers->OptionalHeader.DataDirectory[idx]

// Pointer arithmetics
#define OffsetPointer(data, offset) (void*)((uintptr_t)data + offset)
#define AlignValueUp(value, alignment) (value + alignment - 1) & ~(alignment - 1)
#define AlignValueDown(value, alignment) (value & ~(alignment - 1))

typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef int (WINAPI* ExeEntryProc)(void);

struct ExportNameEntry {
    LPCSTR name;
    WORD idx;
};

typedef struct {
    PIMAGE_NT_HEADERS headers;
    unsigned char* codeBase;
    LONG ntHeadersOffset;
    HMODULE* modules;
    int numModules;
    BOOL initialized;
    BOOL isDLL;
    BOOL isRelocated;
    struct ExportNameEntry* nameExportsTable;
    void* userdata;
    ExeEntryProc exeEntry;
    DWORD pageSize;
} MEMORY_MODULE, * PMEMORY_MODULE;

typedef struct {
    LPVOID address;
    LPVOID alignedAddress;
    SIZE_T size;
    DWORD characteristics;
    BOOL last;
} SECTION_FINALIZE_DATA, * PSECTION_FINALIZE_DATA;

// Protection flags for memory pages (Executable, Readable, Writeable)
static int ProtectionFlags[2][2][2] = {
    {
        // not executable
        {PAGE_NOACCESS, PAGE_WRITECOPY},
        {PAGE_READONLY, PAGE_READWRITE},
    }, {
        // executable
        {PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
        {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
    },
};

class ReflectiveLibraryLoader
{
private:
    static SIZE_T GetRealSectionSize(PMEMORY_MODULE Module, PIMAGE_SECTION_HEADER Section);
    static VOID CopySections(const UCHAR* Data, size_t DataSize, PIMAGE_NT_HEADERS ntHeaders, PMEMORY_MODULE Module);
    static VOID FinalizeSection(PMEMORY_MODULE Module, PSECTION_FINALIZE_DATA SectionData);
    static VOID FinalizeSections(PMEMORY_MODULE Module);
    static VOID ExecuteTLS(PMEMORY_MODULE Module);
    static VOID PerformBaseRelocation(PMEMORY_MODULE Module, ptrdiff_t Delta);
    static VOID BuildImportTable(PMEMORY_MODULE Module);
public:
    static PMEMORY_MODULE MemoryLoadLibrary(const PVOID Data, size_t DataSize);
    static VOID MemoryFreeLibrary(PMEMORY_MODULE Module);
    static VOID OverridePeStringIdentifiers(PMEMORY_MODULE Module);
};