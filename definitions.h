#pragma once
#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#include "config.h"

#define STATUS_SUCCESS 0
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
#define STATUS_OBJECT_PATH_NOT_FOUND 0xC000003A
#define STATUS_PORT_NOT_SET 0xC0000353
#define STATUS_NO_YIELD_PERFORMED 0x40000024

#define ThreadBasicInformation 0

typedef struct _NEWCLIENT_ID { // avoid redefinition of CLIENT_ID
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} NEWCLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef struct _SAVE_DEBUG_REGISTERS {
	DWORD dwThreadId;
	DWORD_PTR Dr0;
	DWORD_PTR Dr1;
	DWORD_PTR Dr2;
	DWORD_PTR Dr3;
	DWORD_PTR Dr6;
	DWORD_PTR Dr7;
} SAVE_DEBUG_REGISTERS;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	KPRIORITY Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _NT_SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
} NT_SYSTEM_PROCESS_INFORMATION, * PNT_SYSTEM_PROCESS_INFORMATION;

typedef struct _NPEB_LDR_DATA {
	uint32_t Length;
	uint8_t Initialized[4];
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} NPEB_LDR_DATA, * NPPEB_LDR_DATA;

typedef struct _INITIAL_TEB {
	struct {
		PVOID OldStackBase;
		PVOID OldStackLimit;
	} OldInitialTeb;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID StackAllocationBase;
} INITIAL_TEB, * PINITIAL_TEB;

typedef struct _WOW64_PROCESS {
	PVOID Wow64;
} WOW64_PROCESS, * PWOW64_PROCESS;

typedef struct _NLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} NLDR_DATA_TABLE_ENTRY, * NPLDR_DATA_TABLE_ENTRY;

typedef struct _NNPEB_LDR_DATA {
	ULONG Length;
	uint8_t Initialized[4];
	ULONG Length2;
	LIST_ENTRY 	InLoadOrderModuleList;
	LIST_ENTRY 	InMemoryOrderModuleList;
	LIST_ENTRY 	InInitializationOrderModuleList;
} NNPEB_LDR_DATA, * NNPPEB_LDR_DATA;

typedef struct _NNPEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	NNPPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} NNPEB, * NNPPEB;

typedef struct _NNPROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	NNPPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} NNPROCESS_BASIC_INFORMATION;
typedef NNPROCESS_BASIC_INFORMATION* NNPPROCESS_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
  LARGE_INTEGER AllocationSize;
  LARGE_INTEGER EndOfFile;
  ULONG         NumberOfLinks;
  BOOLEAN       DeletePending;
  BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef NTSTATUS(WINAPI* __NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
typedef NTSTATUS(NTAPI* __NtGetContextThread__)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* __NtQueryInformationProcess__)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* __NtSetContextThread__)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* __NtContinue__)(PCONTEXT, BOOLEAN);
typedef NTSTATUS(NTAPI* __NtSetInformationThread__)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* __NtYieldExecution__)();
typedef LONG(WINAPI* __NtProtectVirtualMemory__)(HANDLE, PVOID*, PULONG, ULONG, PULONG);
typedef void(NTAPI* __NtRaiseException__)(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN);
typedef NTSTATUS(NTAPI* __NtQueryInformationThread__)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
//typedef NTSTATUS(NTAPI* __RtlSetUnhandledExceptionFilter__)(DWORD TopLevelExceptionFilter); // dword as idk the type, but is 4 bytes 
typedef uint32_t(__stdcall* __KernelBaseSetUnhandledExceptionFilter__)(DWORD TopLevelExceptionFilter);
typedef char(__stdcall* __RtlDispatchException)(_EXCEPTION_RECORD* a1, PCONTEXT context);
typedef void(__stdcall* __RtlCaptureContext)(PCONTEXT ContextRecord);

#endif