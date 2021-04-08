#include "pch.h"
#include "ReflectiveLibraryLoader.h"

inline LPVOID AlignAddressDown(LPVOID address, uintptr_t alignment) {
    return (LPVOID)AlignValueDown((uintptr_t)address, alignment);
}

VOID ReflectiveLibraryLoader::CopySections(const UCHAR* Data, SIZE_T DataSize, PIMAGE_NT_HEADERS ntHeaders, PMEMORY_MODULE Module)
{
    /* Commit a page-aligned DataSize for each Section */

    DWORD i, section_size;
    UCHAR* codeBase = Module->codeBase;
    UCHAR* dest;

    // Loop on each Section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(Module->headers);
    for (i = 0; i < Module->headers->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData == 0) {

            // Section doesn't contain Data in the dll itself, but may define
            // uninitialized Data
            section_size = ntHeaders->OptionalHeader.SectionAlignment;
            if (section_size > 0) {
                dest = (UCHAR*)::VirtualAlloc(codeBase + section->VirtualAddress,
                    section_size,
                    MEM_COMMIT,
                    PAGE_READWRITE);
                if (dest == nullptr)
                    throw;

                // Always use position from file to support alignments smaller
                // than page DataSize (allocation above will align to page DataSize).
                dest = codeBase + section->VirtualAddress;

                // NOTE: On 64bit systems we truncate to 32bit here but expand
                // again later when "PhysicalAddress" is used.
                section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
                ::memset(dest, 0, section_size);
            }

            // Section is empty
            continue;
        }

        if (DataSize < section->PointerToRawData + section->SizeOfRawData) {
            SetLastError(ERROR_INVALID_DATA);
            throw;
        }

        // commit memory block and copy Data from dll
        dest = (UCHAR*)::VirtualAlloc(codeBase + section->VirtualAddress,
            section->SizeOfRawData,
            MEM_COMMIT,
            PAGE_READWRITE);
        if (dest == nullptr)
            throw;

        // Always use position from file to support alignments smaller
        // than page DataSize (allocation above will align to page DataSize).
        dest = codeBase + section->VirtualAddress;
        ::memcpy(dest, Data + section->PointerToRawData, section->SizeOfRawData);

        // NOTE: On 64bit systems we truncate to 32bit here but expand
        // again later when "PhysicalAddress" is used.
        section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
    }
}

SIZE_T ReflectiveLibraryLoader::GetRealSectionSize(PMEMORY_MODULE Module, PIMAGE_SECTION_HEADER Section) {
    DWORD size = Section->SizeOfRawData;
    if (size == 0) {
        if (Section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            size = Module->headers->OptionalHeader.SizeOfInitializedData;
        }
        else if (Section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            size = Module->headers->OptionalHeader.SizeOfUninitializedData;
        }
    }
    return (SIZE_T)size;
}

VOID ReflectiveLibraryLoader::FinalizeSection(PMEMORY_MODULE Module, PSECTION_FINALIZE_DATA SectionData) {

    /* Checks if a Section is discardable and set correct protection flags */

    DWORD protect, oldProtect;
    BOOL executable;
    BOOL readable;
    BOOL writeable;

    if (SectionData->size == 0)
        return;

    if (SectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) {

        // Section is not needed any more and can safely be freed
        if (SectionData->address == SectionData->alignedAddress &&
            (SectionData->last ||
                Module->headers->OptionalHeader.SectionAlignment == Module->pageSize ||
                (SectionData->size % Module->pageSize) == 0)
            ) {
            // Only allowed to decommit whole pages
            ::VirtualFree(SectionData->address, SectionData->size, MEM_DECOMMIT);
        }
        return;
    }

    // Determine protection flags based on characteristics
    executable = (SectionData->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    readable = (SectionData->characteristics & IMAGE_SCN_MEM_READ) != 0;
    writeable = (SectionData->characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    protect = ProtectionFlags[executable][readable][writeable];
    if (SectionData->characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
        protect |= PAGE_NOCACHE;
    }

    // Change memory access flags
    if (!::VirtualProtect(SectionData->address, SectionData->size, protect, &oldProtect))
        throw;
}

VOID ReflectiveLibraryLoader::FinalizeSections(PMEMORY_MODULE Module)
{
    /* Build a SECTION_FINALIZE_DATA structure for each Section and send it to FinalizeSection() */

    DWORD i;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(Module->headers);
#ifdef _WIN64
    // "PhysicalAddress" might have been truncated to 32bit above, expand to
    // 64bits again.
    uintptr_t imageOffset = ((uintptr_t)Module->headers->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
    static const uintptr_t imageOffset = 0;
#endif
    SECTION_FINALIZE_DATA sectionData;
    sectionData.address = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
    sectionData.alignedAddress = AlignAddressDown(sectionData.address, Module->pageSize);
    sectionData.size = GetRealSectionSize(Module, section);
    sectionData.characteristics = section->Characteristics;
    sectionData.last = FALSE;
    section++;

    // Loop through all sections and change access flags
    for (i = 1; i < Module->headers->FileHeader.NumberOfSections; i++, section++) {
        LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
        LPVOID alignedAddress = AlignAddressDown(sectionAddress, Module->pageSize);

        SIZE_T sectionSize = GetRealSectionSize(Module, section);

        // Combine access flags of all sections that share a page
        // TODO(fancycode): We currently share flags of a trailing large Section
        //   with the page of a first small Section. This should be optimized.
        if (sectionData.alignedAddress == alignedAddress || (uintptr_t)sectionData.address + sectionData.size > (uintptr_t) alignedAddress) {

            // Section shares page with previous
            if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0)
                sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
            else
                sectionData.characteristics |= section->Characteristics;

            sectionData.size = (((uintptr_t)sectionAddress) + ((uintptr_t)sectionSize)) - (uintptr_t)sectionData.address;
            continue;
        }

        FinalizeSection(Module, &sectionData);

        sectionData.address = sectionAddress;
        sectionData.alignedAddress = alignedAddress;
        sectionData.size = sectionSize;
        sectionData.characteristics = section->Characteristics;
    }
    sectionData.last = TRUE;

    // Finalize last Section
    FinalizeSection(Module, &sectionData);
}

VOID ReflectiveLibraryLoader::ExecuteTLS(PMEMORY_MODULE Module)
{
    /* Execute Thread Local Storage callbacks if present*/

    UCHAR* codeBase = Module->codeBase;
    PIMAGE_TLS_DIRECTORY tls;
    PIMAGE_TLS_CALLBACK* callback;

    // Get TLS directory
    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(Module, IMAGE_DIRECTORY_ENTRY_TLS);
    if (directory->VirtualAddress == 0)
        return;


    tls = (PIMAGE_TLS_DIRECTORY)(codeBase + directory->VirtualAddress);
    callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
    if (callback) {

        // Loop and execute each callback function
        while (*callback) {
            (*callback)((LPVOID)codeBase, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }
}

VOID ReflectiveLibraryLoader::PerformBaseRelocation(PMEMORY_MODULE Module, ptrdiff_t Delta)
{
    /* Update the relocation table with pointers relative to the module's base address */

    UCHAR* codeBase = Module->codeBase;
    PIMAGE_BASE_RELOCATION relocation;

    // Get relocation directory
    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(Module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (directory->Size == 0 && Delta != 0)
        throw;


    // Loop on each relocation block (i.e. a page containing pointers)
    relocation = (PIMAGE_BASE_RELOCATION)(codeBase + directory->VirtualAddress);
    for (; relocation->VirtualAddress > 0; ) {
        DWORD i;
        UCHAR* dest = codeBase + relocation->VirtualAddress;
        USHORT* relInfo = (USHORT*)OffsetPointer(relocation, IMAGE_SIZEOF_BASE_RELOCATION);

        // Loop on each pointer in the block
        for (i = 0; i < ((relocation->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {

            // The upper 4 bits define the type of relocation
            DWORD type = *relInfo >> 12;
            // The lower 12 bits define the offset
            DWORD offset = *relInfo & 0xfff;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                // Skip relocation
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                // Change complete 32 bit address
            {
                DWORD* patchAddrHL = (DWORD*)(dest + offset);
                *patchAddrHL += (DWORD)Delta;
            }
            break;

#ifdef _WIN64
            case IMAGE_REL_BASED_DIR64:
            {
                ULONGLONG* patchAddr64 = (ULONGLONG*)(dest + offset);
                *patchAddr64 += (ULONGLONG)Delta;
            }
            break;
#endif

            default:
                break;
            }
        }

        // Advance to next relocation block
        relocation = (PIMAGE_BASE_RELOCATION)OffsetPointer(relocation, relocation->SizeOfBlock);
    }
}

VOID ReflectiveLibraryLoader::BuildImportTable(PMEMORY_MODULE Module)
{
    /* Traverse the library's IAT and load each library. Update the function addresses with the correct pointers*/

    UCHAR* codeBase = Module->codeBase;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor;

    // Get import directory
    PIMAGE_DATA_DIRECTORY importDirectory = GET_HEADER_DICTIONARY(Module, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importDirectory->Size == 0)
        return;

    // Allocate initial space for the modules' handles
    Module->modules = (HMODULE*)::HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HMODULE));

    // Loop on each import descriptor
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(codeBase + importDirectory->VirtualAddress);
    for (; !::IsBadReadPtr(importDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDescriptor->Name; importDescriptor++) {
        uintptr_t* thunkRef;
        FARPROC* funcRef;
        HMODULE* tmp;

        // Load decriptor's library
        HMODULE handle = ::LoadLibraryA((LPCSTR)(codeBase + importDescriptor->Name));
        if (handle == nullptr) {
            ::SetLastError(ERROR_MOD_NOT_FOUND);
            throw;
        }

        // Add new module module to the imported modules list (needed in case of freeing)
        tmp = (HMODULE*)::HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Module->modules, (Module->numModules + 1) * (sizeof(HMODULE)));
        if (tmp == nullptr)
            throw;

        Module->modules = tmp;

        // Loop on the imported library's function table
        Module->modules[Module->numModules++] = handle;
        if (importDescriptor->OriginalFirstThunk) {
            thunkRef = (uintptr_t*)(codeBase + importDescriptor->OriginalFirstThunk);
            funcRef = (FARPROC*)(codeBase + importDescriptor->FirstThunk);
        }
        else {

            // No hint table
            thunkRef = (uintptr_t*)(codeBase + importDescriptor->FirstThunk);
            funcRef = (FARPROC*)(codeBase + importDescriptor->FirstThunk);
        }
        for (; *thunkRef; thunkRef++, funcRef++) {

            // Update the table with correct pointers
            if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
                *funcRef = ::GetProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
            }
            else {
                PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(codeBase + (*thunkRef));
                *funcRef = ::GetProcAddress(handle, (LPCSTR)&thunkData->Name);
            }

            if (*funcRef == nullptr)
                throw;
        }
    }
}

VOID ReflectiveLibraryLoader::MemoryFreeLibrary(PMEMORY_MODULE Module)
{
    /* Free the library and all of its imported libraries*/

    if (Module == nullptr)
        return;

    if (Module->initialized) {

        // Notify library about detaching from process
        DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(Module->codeBase + Module->headers->OptionalHeader.AddressOfEntryPoint);
        (*DllEntry)((HINSTANCE)Module->codeBase, DLL_PROCESS_DETACH, 0);
    }

    // Currently not in use
    ::HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Module->nameExportsTable);

    if (Module->modules != nullptr) {

        // Free previously opened libraries        
        for (DWORD i = 0; i < Module->numModules; i++) {
            if (Module->modules[i] != nullptr)
                ::FreeLibrary(Module->modules[i]);
        }

        // Free handle list space
        ::HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Module->modules);
    }

    if (Module->codeBase != nullptr)
        // Release memory of library
        ::VirtualFree(Module->codeBase, 0, MEM_RELEASE);

    ::HeapFree(GetProcessHeap(), 0, Module);
}

PMEMORY_MODULE ReflectiveLibraryLoader::MemoryLoadLibrary(const PVOID Data, SIZE_T DataSize)
{
    /* Loads a library reflectively */

    PMEMORY_MODULE result = nullptr;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    UCHAR* code, * headers;
    ptrdiff_t locationDelta;
    SYSTEM_INFO sysInfo;
    PIMAGE_SECTION_HEADER section;
    SIZE_T optionalSectionSize;
    SIZE_T alignedImageSize;
    SIZE_T lastSectionEnd = 0;

    // Input validity checks
    if (DataSize < sizeof(IMAGE_DOS_HEADER)) {
        SetLastError(ERROR_INVALID_DATA);
        return nullptr;
    }

    dosHeader = (PIMAGE_DOS_HEADER)Data;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        ::SetLastError(ERROR_BAD_EXE_FORMAT);
        return nullptr;
    }

    if (DataSize < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        SetLastError(ERROR_INVALID_DATA);
        return nullptr;
    }

    ntHeaders = (PIMAGE_NT_HEADERS) & ((const UCHAR*)(Data))[dosHeader->e_lfanew];
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        ::SetLastError(ERROR_BAD_EXE_FORMAT);
        return nullptr;
    }

    if (ntHeaders->FileHeader.Machine != HOST_MACHINE) {
        ::SetLastError(ERROR_BAD_EXE_FORMAT);
        return nullptr;
    }

    if (ntHeaders->OptionalHeader.SectionAlignment & 1) {
        // Only support Section alignments that are a multiple of 2
        ::SetLastError(ERROR_BAD_EXE_FORMAT);
        return nullptr;
    }

    if (DataSize < ntHeaders->OptionalHeader.SizeOfHeaders) {
        SetLastError(ERROR_INVALID_DATA);
        return nullptr;
    }


    // Calculate last Section's ending address
    section = IMAGE_FIRST_SECTION(ntHeaders);
    optionalSectionSize = ntHeaders->OptionalHeader.SectionAlignment;
    for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        SIZE_T endOfSection;
        if (section->SizeOfRawData == 0) {
            // Section without Data in the DLL
            endOfSection = section->VirtualAddress + optionalSectionSize;
        }
        else {
            endOfSection = section->VirtualAddress + section->SizeOfRawData;
        }

        if (endOfSection > lastSectionEnd) {
            lastSectionEnd = endOfSection;
        }
    }

    // Calculate page-alligned image DataSize
    ::GetNativeSystemInfo(&sysInfo);
    alignedImageSize = AlignValueUp(ntHeaders->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
    if (alignedImageSize != AlignValueUp(lastSectionEnd, sysInfo.dwPageSize)) {
        ::SetLastError(ERROR_BAD_EXE_FORMAT);
        return nullptr;
    }

    // Commit memory for library's image at its preffered base address
    code = (UCHAR*)::VirtualAlloc((LPVOID)(ntHeaders->OptionalHeader.ImageBase),
        alignedImageSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (code == nullptr) {
        // Address already commited, try to allocate memory at arbitrary position
        code = (UCHAR*)::VirtualAlloc(NULL,
            alignedImageSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (code == nullptr) {
            ::SetLastError(ERROR_OUTOFMEMORY);
            return nullptr;
        }
    }

    // Build MEMORY_MODULE strucute
    result = (PMEMORY_MODULE)::HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORY_MODULE));
    if (result == nullptr) {
        ::VirtualFree(code, 0, MEM_RELEASE);
        ::SetLastError(ERROR_OUTOFMEMORY);
        return nullptr;
    }

    result->codeBase = code;
    result->ntHeadersOffset = dosHeader->e_lfanew;
    result->isDLL = (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    result->pageSize = sysInfo.dwPageSize;

    // Commit memory for headers
    headers = (UCHAR*)::VirtualAlloc(code,
        ntHeaders->OptionalHeader.SizeOfHeaders,
        MEM_COMMIT,
        PAGE_READWRITE);

    // Copy PE header to code
    ::memcpy(headers, dosHeader, ntHeaders->OptionalHeader.SizeOfHeaders);
    result->headers = (PIMAGE_NT_HEADERS) & ((const UCHAR*)(headers))[dosHeader->e_lfanew];

    // Update position
    result->headers->OptionalHeader.ImageBase = (uintptr_t)code;

    try
    {
        // Copy sections from DLL file block to new memory location
        CopySections((const UCHAR*)Data, DataSize, ntHeaders, result);

        // Adjust base address of imported Data
        locationDelta = (ptrdiff_t)(result->headers->OptionalHeader.ImageBase - ntHeaders->OptionalHeader.ImageBase);
        if (locationDelta != 0) {
            PerformBaseRelocation(result, locationDelta);
            result->isRelocated = TRUE;
        }

        // Load required dlls and adjust function table of imports
        BuildImportTable(result);

        // Mark memory pages depending on Section headers and release
        // sections that are marked as "discardable"
        FinalizeSections(result);

        // TLS callbacks are executed BEFORE the main loading
        ExecuteTLS(result);

        // Get entry point of loaded library
        if (result->headers->OptionalHeader.AddressOfEntryPoint != 0) {
            if (result->isDLL) {
                DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);

                // Notify library about attaching to process
                BOOL successful = (*DllEntry)((HINSTANCE)code, DLL_PROCESS_ATTACH, 0);
                if (!successful) {
                    ::SetLastError(ERROR_DLL_INIT_FAILED);
                    throw;
                }
                result->initialized = TRUE;
            }
            else {
                result->exeEntry = (ExeEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
            }
        }
        else {
            result->exeEntry = nullptr;
        }
        return result;
    }

    catch (...) {
        // TODO: Handle each exception accordingly
        // Cleanup
        MemoryFreeLibrary(result);
        return nullptr;
    }
}

VOID ReflectiveLibraryLoader::OverridePeStringIdentifiers(PMEMORY_MODULE Module) {
	
	// Override 'MZ'
    ::memset(Module->codeBase, 0, 2);

	// Override DOS header
    ::memset(Module->codeBase + DOS_HEADER_OFFSET, 0, Module->ntHeadersOffset - DOS_HEADER_OFFSET - sizeof(DWORD) * 2);
}