#pragma once
#include "pch.h"

struct HandleDeleter
{
	void operator()(const HANDLE& handle) const;
};

using AutoHandle = std::unique_ptr<void, HandleDeleter>;