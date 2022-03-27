#pragma once
#ifndef BYPASS_H
#define BYPASS_H
#include "threading.h"
#include "exceptionhandler.h"
#include <map>
#include <string>
#include <winioctl.h>

class Bypass {
public:
	static void Initialize();
	static void Wow64Hook();
	static void WaitAndLogSyscall();
	static void SetExceptionFilter(DWORD TopLevelExceptionFilter);
	static void PatchFreeConsole();
	static void SetKiUserCallback(uintptr_t handler);
	static void PatchHooks();
	static __NtGetContextThread__ GetThreadContext();
	static __NtSetContextThread__ SetThreadContext();
	static void HideDRx();
	static void NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength, int ntStatus);
	static void HkNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions, int& ntOpenFileRetValue);
	static void HkNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, int& ntDeviceIoControlFileValue);
	static void EraseHeaders(HINSTANCE hModule);
	static void UnlinkModule(const wchar_t* dllName);
	static void NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength, int& retValue);
	static void HkNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength, int& ntCreateFileRetValue);
	static void HkNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key, int& ntReadFileRetValue);
	static void HkNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, int& ntQueryInformationFileRetValue);
	static void NtGetContextThreadSysCall(HANDLE ThreadHandle, PCONTEXT ThreadContext);

	static bool ignoreNextThreadContextCall;
	static std::map<uint32_t, std::string> syscallMap;
	static DWORD currentExceptionHandler;
};

#endif