#include <ntifs.h>
#include <minwindef.h>

#define DRIVER_PREFIX "KernelPICCreator: "
#define DRIVER_TAG 'kpic'

struct PicParameters
{
	LPVOID MmGetSystemRoutineAddress;
	LPVOID ReturnedDataAddress;
	USHORT ReturnedDataMaxSize;
};

typedef PVOID(__stdcall* pMmGetSystemRoutineAddress)(_In_ PUNICODE_STRING  SystemRoutineName);
typedef NTSTATUS(__stdcall* pRtlCopyMemory)(_In_  PVOID Destination, _In_  const PVOID Source, _In_ SIZE_T Length);
typedef PEPROCESS(__stdcall* pIoGetCurrentProcess)();
typedef HANDLE(__stdcall* pPsGetProcessId)(_In_ PEPROCESS Process);

#pragma runtime_checks( "", off )
#pragma optimize("", off)

#pragma code_seg(".text$AAAA")
void
__declspec(safebuffers)
__declspec(noinline)
__stdcall PicStart(PVOID StartContext)
{
	// __debugbreak(); // INT 3 for debugging

	if (nullptr == StartContext)
		return;
	
	PicParameters* picParameters = (PicParameters*)StartContext;

	// Get MmGetSystemRoutineAddress
	pMmGetSystemRoutineAddress mmGetSystemRoutineAddress = (pMmGetSystemRoutineAddress)picParameters->MmGetSystemRoutineAddress;
	if (nullptr == mmGetSystemRoutineAddress)
		return;

	// Function names		
	WCHAR ioGetCurrentProcessName[] = { 'P','s','G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s','\0' };
	WCHAR psGetProcessIdName[] = { 'P','s','G','e','t','P','r','o','c','e','s','s','I','d','\0' };
	WCHAR rtlCopyMemoryName[] = { 'R','t','l','C','o','p','y','M','e','m','o','r','y','\0' };
	
	// Create UNICODE_STRING structures
	UNICODE_STRING ioGetCurrentProcessString = RTL_CONSTANT_STRING(ioGetCurrentProcessName);
	UNICODE_STRING psGetProcessIdString = RTL_CONSTANT_STRING(psGetProcessIdName);
	UNICODE_STRING rtlCopyMemoryString = RTL_CONSTANT_STRING(rtlCopyMemoryName);

	// Get function addresses
	pIoGetCurrentProcess ioGetCurrentProcess = (pIoGetCurrentProcess)mmGetSystemRoutineAddress(&ioGetCurrentProcessString);
	pPsGetProcessId psGetProcessId = (pPsGetProcessId)mmGetSystemRoutineAddress(&psGetProcessIdString);
	pRtlCopyMemory rtlCopyMemory = (pRtlCopyMemory)mmGetSystemRoutineAddress(&rtlCopyMemoryString);

	// Check addresses validity
	if (nullptr == ioGetCurrentProcess || nullptr == psGetProcessId || nullptr == rtlCopyMemory)
		return;

	// Get current process object	
	PEPROCESS process = ioGetCurrentProcess();
	if (nullptr == process)
		return;

	// Convert to ULONG and copy to returned data address
	ULONG pid = ::HandleToULong(psGetProcessId(process));
	rtlCopyMemory(picParameters->ReturnedDataAddress, &pid, sizeof(pid));
}

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
{
	// Change per PIC
	USHORT returnedDataMaxSize = sizeof(ULONG);
	
	ULONG* returnedDataAddress = (ULONG*)::ExAllocatePoolWithTag(NonPagedPool, returnedDataMaxSize, DRIVER_TAG);
	if (nullptr == returnedDataAddress) {
		KdPrint((DRIVER_PREFIX "[-] Error allocating returned data space\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	PicParameters picParams;
	picParams.MmGetSystemRoutineAddress = MmGetSystemRoutineAddress;
	picParams.ReturnedDataAddress = returnedDataAddress;
	picParams.ReturnedDataMaxSize = returnedDataMaxSize;
	
	HANDLE threadHandle;
	NTSTATUS status = ::PsCreateSystemThread(
		&threadHandle,
		THREAD_ALL_ACCESS,
		nullptr,
		nullptr,
		nullptr,
		PicStart,
		&picParams);
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

	// Change per PIC
	KdPrint((DRIVER_PREFIX "PIC data returned: %d", *returnedDataAddress));

	::ExFreePoolWithTag(returnedDataAddress, DRIVER_TAG);
	
	return STATUS_SUCCESS;
}
