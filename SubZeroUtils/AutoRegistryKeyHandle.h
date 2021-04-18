#pragma once
#include "Win32ErrorCodeException.h"

class AutoRegistryKeyHandle final
{
public:
	explicit AutoRegistryKeyHandle(const HKEY& handle);

	~AutoRegistryKeyHandle();

	// Delete copy constructor, assignment operator, move constructor, move operator:
	AutoRegistryKeyHandle(const AutoRegistryKeyHandle&) = delete;
	AutoRegistryKeyHandle& operator=(const AutoRegistryKeyHandle&) = delete;
	AutoRegistryKeyHandle(AutoRegistryKeyHandle&&) = delete;
	AutoRegistryKeyHandle& operator=(AutoRegistryKeyHandle&&) = delete;

	/* Set the HKEY member, close the old one if exists. */
	void reset(const HKEY& handle);

	/* Return the HKEY member. */
	HKEY get() const;

protected:
	/* Try to close the HKEY, throw exception if failed. */
	void registryKeyHandleDeleter() const;

	HKEY m_handle;
};