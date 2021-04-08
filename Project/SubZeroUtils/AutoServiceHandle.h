#pragma once
#include "pch.h"
#include "Win32ErrorCodeException.h"

class AutoServiceHandle final
{
public:
	explicit AutoServiceHandle(const SC_HANDLE& handle);

	~AutoServiceHandle();

	// Delete copy constructor, assignment operator, move constructor, move operator:
	AutoServiceHandle(const AutoServiceHandle&) = delete;
	AutoServiceHandle& operator=(const AutoServiceHandle&) = delete;
	AutoServiceHandle(AutoServiceHandle&&) = delete;
	AutoServiceHandle& operator=(AutoServiceHandle&&) = delete;

	/* Set the SC_HANDLE member, close the old one if exists. */
	void reset(const SC_HANDLE& handle);

	/* Return the SC_HANDLE member. */
	SC_HANDLE get() const;

protected:
	/* Try to close the SC_HANDLE, throw exception if failed. */
	void serviceHandleDeleter() const;

	SC_HANDLE m_handle;
};