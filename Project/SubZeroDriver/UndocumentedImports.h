#pragma once
#include "pch.h"

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef
VOID
(*PKNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	);

typedef
VOID
(*PKKERNEL_ROUTINE) (
	IN PKAPC Apc,
	IN OUT PKNORMAL_ROUTINE* NormalRoutine,
	IN OUT PVOID* NormalContext,
	IN OUT PVOID* SystemArgument1,
	IN OUT PVOID* SystemArgument2
	);

typedef
VOID
(*PKRUNDOWN_ROUTINE) (
	IN  PKAPC Apc
	);

extern "C"
VOID
KeInitializeApc(
	IN  PKAPC Apc,
	IN  PKTHREAD Thread,
	IN  KAPC_ENVIRONMENT Environment,
	IN  PKKERNEL_ROUTINE KernelRoutine,
	IN  PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,
	IN  PKNORMAL_ROUTINE NormalRoutine OPTIONAL,
	IN  KPROCESSOR_MODE ApcMode OPTIONAL,
	IN  PVOID NormalContext OPTIONAL
);

extern "C"
BOOLEAN
KeInsertQueueApc(
	IN  PKAPC Apc,
	IN  PVOID SystemArgument1,
	IN  PVOID SystemArgument2,
	IN  KPRIORITY Increment
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PULONG NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
);

extern "C"
NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(
	_In_ PEPROCESS Process
);

extern "C"
NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(
	_In_ PEPROCESS Process
);




typedef struct _CONTROL_AREA {
	PVOID Segment;						// PSEGMENT
	LIST_ENTRY DereferenceList;
	ULONG NumberOfSectionReferences;    // All section refs & image flushes
	ULONG NumberOfPfnReferences;        // valid + transition prototype PTEs
	ULONG NumberOfMappedViews;          // total # mapped views, including
										// system cache & system space views
	ULONG NumberOfSystemCacheViews;     // system cache views only
	ULONG NumberOfUserReferences;       // user section & view references
	union {
		ULONG LongFlags;
		ULONG Flags;					// MMSECTION_FLAGS
	} u;
	PFILE_OBJECT FilePointer;
	PVOID WaitingForDeletion;			// PEVENT_COUNTER 
	USHORT ModifiedWriteCount;
	USHORT FlushInProgressCount;
	ULONG WritableUserReferences;
#if !defined (_WIN64)
	ULONG QuadwordPad;
#endif
} CONTROL_AREA, * PCONTROL_AREA;

//0x4 bytes (sizeof)
typedef struct _MMVAD_FLAGS
{
	ULONG Lock : 1;                                                           //0x0
	ULONG LockContended : 1;                                                  //0x0
	ULONG DeleteInProgress : 1;                                               //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG VadType : 3;                                                        //0x0
	ULONG Protection : 5;                                                     //0x0
	ULONG PreferredNode : 6;                                                  //0x0
	ULONG PageSize : 2;                                                       //0x0
	ULONG PrivateMemory : 1;                                                  //0x0
} MMVAD_FLAGS, * PMMVAD_FLAGS;

typedef struct _MMVAD_FLAGS2 {
	unsigned FileOffset : 24;       // number of 64k units into file
	unsigned SecNoChange : 1;       // set if SEC_NOCHANGE specified
	unsigned OneSecured : 1;        // set if u3 field is a range
	unsigned MultipleSecured : 1;   // set if u3 field is a list head
	unsigned ReadOnly : 1;          // protected as ReadOnly
	unsigned LongVad : 1;           // set if VAD is a long VAD
	unsigned ExtendableFile : 1;
	unsigned Inherit : 1;           //1 = ViewShare, 0 = ViewUnmap
	unsigned CopyOnWrite : 1;
} MMVAD_FLAGS2;

typedef struct _MMADDRESS_NODE
{
	ULONG u1;
	PVOID LeftChild;    // PMMADDRESS_NODE
	PVOID RightChild;   // PMMADDRESS_NODE
	ULONG StartingVpn;
	ULONG EndingVpn;
} MMADDRESS_NODE, * PMMADDRESS_NODE;

typedef struct _MM_AVL_TABLE
{
	MMADDRESS_NODE BalancedRoot;
	ULONG DepthOfTree : 5;
	ULONG Unused : 3;
	ULONG NumberGenericTableElements : 24;
	PVOID NodeHint;
	PVOID NodeFreeHint;
} MM_AVL_TABLE, * PMM_AVL_TABLE;

//0x40 bytes (sizeof)
typedef struct _MMVAD_SHORT
{
	union
	{
		struct
		{
			_MMVAD_SHORT* NextVad;											//0x0
			VOID* ExtraCreateInfo;                                          //0x8
		}v;
		_RTL_BALANCED_NODE VadNode;											//0x0
	};
	ULONG StartingVpn;                                                      //0x18
	ULONG EndingVpn;                                                        //0x1c
	UCHAR StartingVpnHigh;                                                  //0x20
	UCHAR EndingVpnHigh;                                                    //0x21
	UCHAR CommitChargeHigh;                                                 //0x22
	UCHAR SpareNT64VadUChar;                                                //0x23
	LONG ReferenceCount;                                                    //0x24
	PVOID PushLock;															//0x28 - _EX_PUSH_LOCK 
	union
	{
		ULONG LongFlags;                                                    //0x30
		MMVAD_FLAGS VadFlags;												//0x30
		ULONG PrivateVadFlags;												//0x30 - _MM_PRIVATE_VAD_FLAGS 
		ULONG GraphicsVadFlags;												//0x30 - _MM_GRAPHICS_VAD_FLAGS 
		ULONG SharedVadFlags;												//0x30 - _MM_SHARED_VAD_FLAGS 
		volatile ULONG VolatileVadLong;                                     //0x30
	} u;                                                                    //0x30
	union
	{
		ULONG LongFlags1;                                                   //0x34
		ULONG VadFlags1;				                                    //0x34 - _MMVAD_FLAGS1
	} u1;                                                                   //0x34
	struct _MI_VAD_EVENT_BLOCK* EventList;                                  //0x38
} MMVAD_SHORT, * PMMVAD_SHORT;

typedef struct _MMVAD
{
	MMVAD_SHORT Core;														//0x0
	union
	{
		ULONG LongFlags2;                                                   //0x40
		volatile _MMVAD_FLAGS2 VadFlags2;									//0x40
	} u2;                                                                   //0x40
	PVOID Subsection;														//0x48 - _PSUBSECTION
	PVOID FirstPrototypePte;												//0x50 - _PMMPTE 
	PVOID LastContiguousPte;												//0x58 - _PMMPTE 
	LIST_ENTRY ViewLinks;													//0x60
	PEPROCESS VadsProcess;													//0x70
	union
	{
		PVOID SequentialVa;													//0x78 - _MI_VAD_SEQUENTIAL_INFO
		PVOID ExtendedInfo;													//0x78 - _MMEXTEND_INFO
	} u4;                                                                   //0x78
	PFILE_OBJECT FileObject;												//0x80
} MMVAD, * PMMVAD;

