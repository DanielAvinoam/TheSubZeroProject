#include "pch.h"
#include "ReflectiveLibraryLoader.h"

#if _MSC_VER
// Disable warning about data -> function pointer conversion
#pragma warning(disable:4055)
 // C4244: conversion from 'uintptr_t' to 'DWORD', possible loss of data.
#pragma warning(error: 4244)
// C4267: conversion from 'size_t' to 'int', possible loss of data.
#pragma warning(error: 4267)

#define inline __inline
#endif

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

#include "ReflectiveLibraryLoader.h"
#define GET_HEADER_DICTIONARY(module, idx)  &(module)->headers->OptionalHeader.DataDirectory[idx]

static inline uintptr_t AlignValueDown(uintptr_t value, uintptr_t alignment) {
    return value & ~(alignment - 1);
}

static inline LPVOID AlignAddressDown(LPVOID address, uintptr_t alignment) {
    return (LPVOID)AlignValueDown((uintptr_t)address, alignment);
}

static inline size_t AlignValueUp(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline void* OffsetPointer(void* data, ptrdiff_t offset) {
    return (void*)((uintptr_t)data + offset);
}

#ifdef _WIN64
static void FreePointerList(POINTER_LIST* head)
{
    POINTER_LIST* node = head;
    while (node) {
        POINTER_LIST* next;
        VirtualFree(node->address, 0, MEM_RELEASE);
        next = node->next;
        free(node);
        node = next;
    }
}
#endif

static BOOL CheckSize(size_t size, size_t expected) {
    if (size < expected) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    return TRUE;
}

static BOOL CopySections(const unsigned char* data, size_t size, PIMAGE_NT_HEADERS old_headers, PMEMORYMODULE module)
{
    int i, section_size;
    unsigned char* codeBase = module->codeBase;
    unsigned char* dest;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
    for (i = 0; i < module->headers->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData == 0) {
            // section doesn't contain data in the dll itself, but may define
            // uninitialized data
            section_size = old_headers->OptionalHeader.SectionAlignment;
            if (section_size > 0) {
                dest = (unsigned char*)::VirtualAlloc(codeBase + section->VirtualAddress,
                    section_size,
                    MEM_COMMIT,
                    PAGE_READWRITE);
                if (dest == NULL) {
                    return FALSE;
                }

                // Always use position from file to support alignments smaller
                // than page size (allocation above will align to page size).
                dest = codeBase + section->VirtualAddress;
                // NOTE: On 64bit systems we truncate to 32bit here but expand
                // again later when "PhysicalAddress" is used.
                section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
                memset(dest, 0, section_size);
            }

            // section is empty
            continue;
        }

        if (!CheckSize(size, section->PointerToRawData + section->SizeOfRawData)) {
            return FALSE;
        }

        // commit memory block and copy data from dll
        dest = (unsigned char*)::VirtualAlloc(codeBase + section->VirtualAddress,
            section->SizeOfRawData,
            MEM_COMMIT,
            PAGE_READWRITE);
        if (dest == NULL) {
            return FALSE;
        }

        // Always use position from file to support alignments smaller
        // than page size (allocation above will align to page size).
        dest = codeBase + section->VirtualAddress;
        memcpy(dest, data + section->PointerToRawData, section->SizeOfRawData);
        // NOTE: On 64bit systems we truncate to 32bit here but expand
        // again later when "PhysicalAddress" is used.
        section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
    }

    return TRUE;
}

static SIZE_T GetRealSectionSize(PMEMORYMODULE module, PIMAGE_SECTION_HEADER section) {
    DWORD size = section->SizeOfRawData;
    if (size == 0) {
        if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            size = module->headers->OptionalHeader.SizeOfInitializedData;
        }
        else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            size = module->headers->OptionalHeader.SizeOfUninitializedData;
        }
    }
    return (SIZE_T)size;
}

static BOOL FinalizeSection(PMEMORYMODULE module, PSECTIONFINALIZEDATA sectionData) {
    DWORD protect, oldProtect;
    BOOL executable;
    BOOL readable;
    BOOL writeable;

    if (sectionData->size == 0) {
        return TRUE;
    }

    if (sectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
        // section is not needed any more and can safely be freed
        if (sectionData->address == sectionData->alignedAddress &&
            (sectionData->last ||
                module->headers->OptionalHeader.SectionAlignment == module->pageSize ||
                (sectionData->size % module->pageSize) == 0)
            ) {
            // Only allowed to decommit whole pages
            ::VirtualFree(sectionData->address, sectionData->size, MEM_DECOMMIT);
        }
        return TRUE;
    }

    // determine protection flags based on characteristics
    executable = (sectionData->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    readable = (sectionData->characteristics & IMAGE_SCN_MEM_READ) != 0;
    writeable = (sectionData->characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    protect = ProtectionFlags[executable][readable][writeable];
    if (sectionData->characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
        protect |= PAGE_NOCACHE;
    }

    // change memory access flags
    if (VirtualProtect(sectionData->address, sectionData->size, protect, &oldProtect) == 0) {
        return FALSE;
    }

    return TRUE;
}

static BOOL FinalizeSections(PMEMORYMODULE module)
{
    int i;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
#ifdef _WIN64
    // "PhysicalAddress" might have been truncated to 32bit above, expand to
    // 64bits again.
    uintptr_t imageOffset = ((uintptr_t)module->headers->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
    static const uintptr_t imageOffset = 0;
#endif
    SECTIONFINALIZEDATA sectionData;
    sectionData.address = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
    sectionData.alignedAddress = AlignAddressDown(sectionData.address, module->pageSize);
    sectionData.size = GetRealSectionSize(module, section);
    sectionData.characteristics = section->Characteristics;
    sectionData.last = FALSE;
    section++;

    // loop through all sections and change access flags
    for (i = 1; i < module->headers->FileHeader.NumberOfSections; i++, section++) {
        LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
        LPVOID alignedAddress = AlignAddressDown(sectionAddress, module->pageSize);
        SIZE_T sectionSize = GetRealSectionSize(module, section);
        // Combine access flags of all sections that share a page
        // TODO(fancycode): We currently share flags of a trailing large section
        //   with the page of a first small section. This should be optimized.
        if (sectionData.alignedAddress == alignedAddress || (uintptr_t)sectionData.address + sectionData.size > (uintptr_t) alignedAddress) {
            // Section shares page with previous
            if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
                sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
            }
            else {
                sectionData.characteristics |= section->Characteristics;
            }
            sectionData.size = (((uintptr_t)sectionAddress) + ((uintptr_t)sectionSize)) - (uintptr_t)sectionData.address;
            continue;
        }

        if (!FinalizeSection(module, &sectionData)) {
            return FALSE;
        }
        sectionData.address = sectionAddress;
        sectionData.alignedAddress = alignedAddress;
        sectionData.size = sectionSize;
        sectionData.characteristics = section->Characteristics;
    }
    sectionData.last = TRUE;
    if (!FinalizeSection(module, &sectionData)) {
        return FALSE;
    }
    return TRUE;
}

static BOOL ExecuteTLS(PMEMORYMODULE module)
{
    unsigned char* codeBase = module->codeBase;
    PIMAGE_TLS_DIRECTORY tls;
    PIMAGE_TLS_CALLBACK* callback;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_TLS);
    if (directory->VirtualAddress == 0) {
        return TRUE;
    }

    tls = (PIMAGE_TLS_DIRECTORY)(codeBase + directory->VirtualAddress);
    callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
    if (callback) {
        while (*callback) {
            (*callback)((LPVOID)codeBase, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }
    return TRUE;
}

static BOOL PerformBaseRelocation(PMEMORYMODULE module, ptrdiff_t delta)
{
    unsigned char* codeBase = module->codeBase;
    PIMAGE_BASE_RELOCATION relocation;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (directory->Size == 0) {
        return (delta == 0);
    }

    relocation = (PIMAGE_BASE_RELOCATION)(codeBase + directory->VirtualAddress);
    for (; relocation->VirtualAddress > 0; ) {
        DWORD i;
        unsigned char* dest = codeBase + relocation->VirtualAddress;
        unsigned short* relInfo = (unsigned short*)OffsetPointer(relocation, IMAGE_SIZEOF_BASE_RELOCATION);
        for (i = 0; i < ((relocation->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
            // the upper 4 bits define the type of relocation
            int type = *relInfo >> 12;
            // the lower 12 bits define the offset
            int offset = *relInfo & 0xfff;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                // skip relocation
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                // change complete 32 bit address
            {
                DWORD* patchAddrHL = (DWORD*)(dest + offset);
                *patchAddrHL += (DWORD)delta;
            }
            break;

#ifdef _WIN64
            case IMAGE_REL_BASED_DIR64:
            {
                ULONGLONG* patchAddr64 = (ULONGLONG*)(dest + offset);
                *patchAddr64 += (ULONGLONG)delta;
            }
            break;
#endif

            default:
                //printf("Unknown relocation: %d\n", type);
                break;
            }
        }

        // advance to next relocation block
        relocation = (PIMAGE_BASE_RELOCATION)OffsetPointer(relocation, relocation->SizeOfBlock);
    }
    return TRUE;
}

static BOOL BuildImportTable(PMEMORYMODULE module)
{
    unsigned char* codeBase = module->codeBase;
    PIMAGE_IMPORT_DESCRIPTOR importDesc;
    BOOL result = TRUE;

    PIMAGE_DATA_DIRECTORY importDirectory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importDirectory->Size == 0) {
        return TRUE;
    }

    importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(codeBase + importDirectory->VirtualAddress);
    for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++) {
        uintptr_t* thunkRef;
        FARPROC* funcRef;
        HCUSTOMMODULE* tmp;
        HCUSTOMMODULE handle = LoadLibraryA((LPCSTR)(codeBase + importDesc->Name));
        if (handle == NULL) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            result = FALSE;
            break;
        }

        tmp = (HCUSTOMMODULE*)realloc(module->modules, (module->numModules + 1) * (sizeof(HCUSTOMMODULE)));
        if (tmp == NULL) {
            ::FreeLibrary(handle);
            SetLastError(ERROR_OUTOFMEMORY);
            result = FALSE;
            break;
        }
        module->modules = tmp;

        module->modules[module->numModules++] = handle;
        if (importDesc->OriginalFirstThunk) {
            thunkRef = (uintptr_t*)(codeBase + importDesc->OriginalFirstThunk);
            funcRef = (FARPROC*)(codeBase + importDesc->FirstThunk);
        }
        else {
            // no hint table
            thunkRef = (uintptr_t*)(codeBase + importDesc->FirstThunk);
            funcRef = (FARPROC*)(codeBase + importDesc->FirstThunk);
        }
        for (; *thunkRef; thunkRef++, funcRef++) {
            if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
                *funcRef = ::GetProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
            }
            else {
                PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(codeBase + (*thunkRef));
                *funcRef = ::GetProcAddress(handle, (LPCSTR)&thunkData->Name);
            }
            if (*funcRef == 0) {
                result = FALSE;
                break;
            }
        }

        if (!result) {
            ::FreeLibrary(handle);
            SetLastError(ERROR_PROC_NOT_FOUND);
            break;
        }
    }

    return result;
}

void ReflectiveLibraryLoader::MemoryFreeLibrary(HMEMORYMODULE mod)
{
    PMEMORYMODULE module = (PMEMORYMODULE)mod;

    if (module == NULL) {
        return;
    }
    if (module->initialized) {
        // notify library about detaching from process
        DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(module->codeBase + module->headers->OptionalHeader.AddressOfEntryPoint);
        (*DllEntry)((HINSTANCE)module->codeBase, DLL_PROCESS_DETACH, 0);
    }

    free(module->nameExportsTable);
    if (module->modules != NULL) {
        // free previously opened libraries
        int i;
        for (i = 0; i < module->numModules; i++) {
            if (module->modules[i] != NULL) {
                ::FreeLibrary(module->modules[i]);
            }
        }

        free(module->modules);
    }

    if (module->codeBase != NULL) {
        // release memory of library
        ::VirtualFree(module->codeBase, 0, MEM_RELEASE);
    }

#ifdef _WIN64
    FreePointerList(module->blockedMemory);
#endif
    HeapFree(GetProcessHeap(), 0, module);
}

HMEMORYMODULE ReflectiveLibraryLoader::MemoryLoadLibrary(const void* data, size_t size)
{
    PMEMORYMODULE result = NULL;
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS old_header;
    unsigned char* code, * headers;
    ptrdiff_t locationDelta;
    SYSTEM_INFO sysInfo;
    PIMAGE_SECTION_HEADER section;
    DWORD i;
    size_t optionalSectionSize;
    size_t lastSectionEnd = 0;
    size_t alignedImageSize;
#ifdef _WIN64
    POINTER_LIST* blockedMemory = NULL;
#endif

    // Input validity checks
    if (!CheckSize(size, sizeof(IMAGE_DOS_HEADER))) return NULL;

    dos_header = (PIMAGE_DOS_HEADER)data;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    if (!CheckSize(size, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS))) return NULL;
    
    old_header = (PIMAGE_NT_HEADERS) & ((const unsigned char*)(data))[dos_header->e_lfanew];
    if (old_header->Signature != IMAGE_NT_SIGNATURE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    if (old_header->FileHeader.Machine != HOST_MACHINE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    if (old_header->OptionalHeader.SectionAlignment & 1) {
        // Only support section alignments that are a multiple of 2
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }


    // Calculate last section's ending address
    section = IMAGE_FIRST_SECTION(old_header);
    optionalSectionSize = old_header->OptionalHeader.SectionAlignment;
    for (i = 0; i < old_header->FileHeader.NumberOfSections; i++, section++) {
        size_t endOfSection;
        if (section->SizeOfRawData == 0) {
            // Section without data in the DLL
            endOfSection = section->VirtualAddress + optionalSectionSize;
        }
        else {
            endOfSection = section->VirtualAddress + section->SizeOfRawData;
        }

        if (endOfSection > lastSectionEnd) {
            lastSectionEnd = endOfSection;
        }
    }

    // Calculate page-alligned image size
    GetNativeSystemInfo(&sysInfo);
    alignedImageSize = AlignValueUp(old_header->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
    if (alignedImageSize != AlignValueUp(lastSectionEnd, sysInfo.dwPageSize)) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }


    // TODO: Kernel Allocations
    // reserve memory for image of library
    // XXX: is it correct to commit the complete memory region at once?
    //      calling DllEntry raises an exception if we don't...
    code = (unsigned char*)VirtualAlloc((LPVOID)(old_header->OptionalHeader.ImageBase),
        alignedImageSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (code == NULL) {
        // try to allocate memory at arbitrary position
        code = (unsigned char*)VirtualAlloc(NULL,
            alignedImageSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (code == NULL) {
            SetLastError(ERROR_OUTOFMEMORY);
            return NULL;
        }
    }

#ifdef _WIN64
    // Memory block may not span 4 GB boundaries.
    while ((((uintptr_t)code) >> 32) < (((uintptr_t)(code + alignedImageSize)) >> 32)) {
        POINTER_LIST* node = (POINTER_LIST*)malloc(sizeof(POINTER_LIST));
        if (!node) {
            VirtualFree(code, 0, MEM_RELEASE);
            FreePointerList(blockedMemory);
            SetLastError(ERROR_OUTOFMEMORY);
            return NULL;
        }

        node->next = blockedMemory;
        node->address = code;
        blockedMemory = node;

        code = (unsigned char*)VirtualAlloc(NULL,
            alignedImageSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (code == NULL) {
            FreePointerList(blockedMemory);
            SetLastError(ERROR_OUTOFMEMORY);
            return NULL;
        }
    }
#endif

    result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORYMODULE));
    if (result == NULL) {
        VirtualFree(code, 0, MEM_RELEASE);
#ifdef _WIN64
        FreePointerList(blockedMemory);
#endif
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    result->codeBase = code;
    result->isDLL = (old_header->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    result->pageSize = sysInfo.dwPageSize;
#ifdef _WIN64
    result->blockedMemory = blockedMemory;
#endif

    if (!CheckSize(size, old_header->OptionalHeader.SizeOfHeaders)) {
        goto error;
    }

    // commit memory for headers
    headers = (unsigned char*)VirtualAlloc(code,
        old_header->OptionalHeader.SizeOfHeaders,
        MEM_COMMIT,
        PAGE_READWRITE);

    // copy PE header to code
    memcpy(headers, dos_header, old_header->OptionalHeader.SizeOfHeaders);
    result->headers = (PIMAGE_NT_HEADERS) & ((const unsigned char*)(headers))[dos_header->e_lfanew];

    // update position
    result->headers->OptionalHeader.ImageBase = (uintptr_t)code;

    // copy sections from DLL file block to new memory location
    if (!CopySections((const unsigned char*)data, size, old_header, result)) {
        goto error;
    }

    // adjust base address of imported data
    locationDelta = (ptrdiff_t)(result->headers->OptionalHeader.ImageBase - old_header->OptionalHeader.ImageBase);
    if (locationDelta != 0) {
        result->isRelocated = PerformBaseRelocation(result, locationDelta);
    }
    else {
        result->isRelocated = TRUE;
    }


    // load required dlls and adjust function table of imports
    if (!BuildImportTable(result)) {
        goto error;
    }

    // mark memory pages depending on section headers and release
    // sections that are marked as "discardable"
    if (!FinalizeSections(result)) {
        goto error;
    }

    // TLS callbacks are executed BEFORE the main loading
    if (!ExecuteTLS(result)) {
        goto error;
    }

    // get entry point of loaded library
    if (result->headers->OptionalHeader.AddressOfEntryPoint != 0) {
        if (result->isDLL) {
            DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
            // notify library about attaching to process
            BOOL successfull = (*DllEntry)((HINSTANCE)code, DLL_PROCESS_ATTACH, 0);
            if (!successfull) {
                SetLastError(ERROR_DLL_INIT_FAILED);
                goto error;
            }
            result->initialized = TRUE;
        }
        else {
            result->exeEntry = (ExeEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
        }
    }
    else {
        result->exeEntry = NULL;
    }

    return (HMEMORYMODULE)result;

error:
    // cleanup
    MemoryFreeLibrary(result);
    return NULL;
}