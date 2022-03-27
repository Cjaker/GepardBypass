#pragma once
#ifndef THREADING_H
#define THREADING_H
#include <Windows.h>
#include <time.h>

class Threading {
public:
	static HANDLE CreateFakeThread(LPVOID thread);

	// drx threading methods
	static void ThreadDebugContextRemoveEntry(const int index);
	static void ThreadRetrieveSavedContext(PCONTEXT threadContext, const int index);
	static void ThreadDebugContextSaveContext(const int index, const PCONTEXT threadContext);
	static void ClearThreadContext(PCONTEXT threadContext);
	static int ThreadDebugContextFindExistingSlotIndex();
	static int ThreadDebugContextFindFreeSlotIndex();
	static uint32_t GetCurrentBreakpointAddress(const PCONTEXT threadContext);
	static int GetCurrentBreakpointIndex(const PCONTEXT threadContext);
	static void Sleep(int milliseconds);
	static DWORD GetProcessIdByThreadHandle(HANDLE hThread);

	static SAVE_DEBUG_REGISTERS ArrayDebugRegister[100];
};

#endif