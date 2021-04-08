#include "pch.h"
#include "AutoRegistryKeyHandle.h"

AutoRegistryKeyHandle::AutoRegistryKeyHandle(const HKEY& handle)
	: m_handle(handle)
{
}

AutoRegistryKeyHandle::~AutoRegistryKeyHandle()
{
	try
	{
		this->registryKeyHandleDeleter();
	}
	catch (...)
	{
		// Intentionally left black
	}
}

void AutoRegistryKeyHandle::reset(const HKEY& handle)
{
	if (nullptr != this->m_handle)
	{
		this->registryKeyHandleDeleter();
	}

	this->m_handle = handle;
}

HKEY AutoRegistryKeyHandle::get() const
{
	return this->m_handle;
}

void AutoRegistryKeyHandle::registryKeyHandleDeleter() const
{
	if (nullptr != this->m_handle)
	{
		if (!::RegCloseKey(this->m_handle))
		{
			throw Win32ErrorCodeException("Could not close the registry key handle");
		}
	}
}