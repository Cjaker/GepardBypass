#include "pch.h"
#include "threading.h"

SAVE_DEBUG_REGISTERS Threading::ArrayDebugRegister[100] = { 0 };
// TODO: Terminate thread if he's gonna be suspended only.
HANDLE Threading::CreateFakeThread(LPVOID thread) {
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	HANDLE tHand = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)0x0, NULL, CREATE_SUSPENDED, NULL);
	if (tHand == NULL)
		return NULL;

	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
	if (ntdllModule == NULL) {
		return NULL;
	}

	FARPROC getContextThread = GetProcAddress(ntdllModule, "NtGetContextThread");
	if (getContextThread == NULL) {
		return NULL;
	}

	NTSTATUS status = ((__NtGetContextThread__)(getContextThread))(tHand, &ctx);
	if (status != STATUS_SUCCESS)
		return NULL;

	ctx.Eax = (DWORD)thread;
	SetThreadContext(tHand, &ctx);
	ResumeThread(tHand);
	return tHand;
}

void Threading::ThreadDebugContextRemoveEntry(const int index) {
	Threading::ArrayDebugRegister[index].dwThreadId = 0;
}

void Threading::ThreadRetrieveSavedContext(PCONTEXT threadContext, const int index) {
	threadContext->Dr0 = Threading::ArrayDebugRegister[index].Dr0;
	threadContext->Dr1 = Threading::ArrayDebugRegister[index].Dr1;
	threadContext->Dr2 = Threading::ArrayDebugRegister[index].Dr2;
	threadContext->Dr3 = Threading::ArrayDebugRegister[index].Dr3;
	threadContext->Dr6 = Threading::ArrayDebugRegister[index].Dr6;
	threadContext->Dr7 = Threading::ArrayDebugRegister[index].Dr7;
}

void Threading::ThreadDebugContextSaveContext(const int index, const PCONTEXT threadContext) {
	Threading::ArrayDebugRegister[index].dwThreadId = HandleToULong(GetCurrentThreadId());
	Threading::ArrayDebugRegister[index].Dr0 = threadContext->Dr0;
	Threading::ArrayDebugRegister[index].Dr1 = threadContext->Dr1;
	Threading::ArrayDebugRegister[index].Dr2 = threadContext->Dr2;
	Threading::ArrayDebugRegister[index].Dr3 = threadContext->Dr3;
	Threading::ArrayDebugRegister[index].Dr6 = threadContext->Dr6;
	Threading::ArrayDebugRegister[index].Dr7 = threadContext->Dr7;
}

void Threading::ClearThreadContext(PCONTEXT threadContext) {
	threadContext->Dr0 = 0;
	threadContext->Dr1 = 0;
	threadContext->Dr2 = 0;
	threadContext->Dr3 = 0;
	threadContext->Dr6 = 0;
	threadContext->Dr7 = 0;
}

int Threading::ThreadDebugContextFindExistingSlotIndex() {
	for (int i = 0; i < _countof(Threading::ArrayDebugRegister); i++) {
		if (Threading::ArrayDebugRegister[i].dwThreadId != 0) {
			if (Threading::ArrayDebugRegister[i].dwThreadId == HandleToULong(GetCurrentThreadId())) {
				return i;
			}
		}
	}

	return -1;
}

int Threading::ThreadDebugContextFindFreeSlotIndex() {
	for (int i = 0; i < _countof(Threading::ArrayDebugRegister); i++) {
		if (Threading::ArrayDebugRegister[i].dwThreadId == 0) {
			return i;
		}
	}

	return -1;
}

uint32_t Threading::GetCurrentBreakpointAddress(const PCONTEXT threadContext) {
	DWORD contextDr6 = threadContext->Dr6;
	DWORD firstDrAddress = (DWORD)&threadContext->Dr0;
	for (int index = 0; index < 4; index++) {
		if (((contextDr6 >> index) & 1) == 1) {
			return *((DWORD*)(firstDrAddress + (index * sizeof(DWORD))));
		}
	}

	return 0;
}

int Threading::GetCurrentBreakpointIndex(const PCONTEXT threadContext) {
	DWORD contextDr6 = threadContext->Dr6;
	for (int index = 0; index < 4; index++) {
		if (((contextDr6 >> index) & 1) == 1) {
			return index;
		}
	}

	return -1;
}

void Threading::Sleep(int milliseconds) {
	clock_t time_end;
	time_end = clock() + milliseconds * CLOCKS_PER_SEC / 1000;
	while (clock() < time_end) {
	}
}

DWORD Threading::GetProcessIdByThreadHandle(HANDLE hThread) {
	THREAD_BASIC_INFORMATION tbi;

	if (NT_SUCCESS(NtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadBasicInformation, &tbi, sizeof(THREAD_BASIC_INFORMATION), 0))) {
		return HandleToULong(tbi.ClientId.UniqueProcess);
	}

	return 0;
}
