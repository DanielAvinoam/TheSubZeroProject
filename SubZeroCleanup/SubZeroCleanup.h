#pragma once
#include "pch.h"

class SubZeroCleanup
{
	static std::uint32_t GetProcessPidByProcessName(const std::wstring& processName);

public:
	static void Cleanup();
};