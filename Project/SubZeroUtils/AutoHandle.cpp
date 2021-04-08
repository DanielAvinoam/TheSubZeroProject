#include "pch.h"
#include "AutoHandle.h"

void HandleDeleter::operator()(const HANDLE& handle) const
{
	if (INVALID_HANDLE_VALUE != handle)
	{
		CloseHandle(handle);
	}
}