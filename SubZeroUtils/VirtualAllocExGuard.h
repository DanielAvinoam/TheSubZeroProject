#pragma once
#include <Windows.h>

class VirtualAllocExGuard
{
public:
	explicit VirtualAllocExGuard(const HANDLE& process, SIZE_T allocationSize, DWORD protection, DWORD allocationType = MEM_COMMIT, LPVOID address = nullptr);

	virtual ~VirtualAllocExGuard();

	// Disable: copyable, cloneable, movable:
	VirtualAllocExGuard(const VirtualAllocExGuard&) = delete;
	VirtualAllocExGuard& operator=(const VirtualAllocExGuard&) = delete;
	VirtualAllocExGuard(VirtualAllocExGuard&&) = delete;
	VirtualAllocExGuard& operator=(VirtualAllocExGuard&&) = delete;

	LPVOID get() const;

	void release();

private:
	void free() const;

	HANDLE m_process;
	LPVOID m_address;
	SIZE_T m_allocationSize;
};