#include "pch.h"
#include "PISInjection.h"

void PISInjection::writeToTargetProcess(HANDLE targetProcess, LPVOID remoteAddress, LPVOID data, SIZE_T dataSize)
{
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(targetProcess, remoteAddress, data, dataSize, &bytesWritten))
	{
		throw Win32ErrorCodeException("Could not write PIS parameters to target process memory");
	}
}