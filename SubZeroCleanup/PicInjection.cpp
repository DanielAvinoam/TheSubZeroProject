#include "pch.h"
#include "PicInjection.h"

void PicInjection::writeToTargetProcess(HANDLE targetProcess, LPVOID remoteAddress, LPVOID data, SIZE_T dataSize)
{
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(targetProcess, remoteAddress, data, dataSize, &bytesWritten))
	{
		throw Win32ErrorCodeException("Could not write PIC parameters to target process memory");
	}
}