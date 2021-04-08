#include "pch.h"
#include "AutoServiceHandle.h"
#include "Win32ErrorCodeException.h"

AutoServiceHandle::AutoServiceHandle(const SC_HANDLE& handle)
	: m_handle(handle)
{
}

AutoServiceHandle::~AutoServiceHandle()
{
	try
	{
		this->serviceHandleDeleter();
	}
	catch (...)
	{
		// Intentionally left black
	}
}

void AutoServiceHandle::reset(const SC_HANDLE& handle)
{
	if (nullptr != this->m_handle)
	{
		this->serviceHandleDeleter();
	}

	this->m_handle = handle;
}

SC_HANDLE AutoServiceHandle::get() const
{
	return this->m_handle;
}

void AutoServiceHandle::serviceHandleDeleter() const
{
	if (nullptr != this->m_handle)
	{
		if (!CloseServiceHandle(this->m_handle))
		{
			throw Win32ErrorCodeException("Could not close the service handle");
		}
	}
}