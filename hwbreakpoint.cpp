#include "pch.h"
#include "hwbreakpoint.h"

bool initialized = false;
void* addresses[4];
int len[4];
HWBreakpoint::Condition conditions[4];

std::thread workerThread;
std::mutex workerMutex, controlMutex;
std::condition_variable workerSignal;
std::atomic<bool> workerStop;
volatile DWORD pendingThread;

bool HWBreakpoint::ignoreNextThreadContextCall = false;

inline void HWBreakpoint::SetBits(ULONG_PTR& dw, int lowBit, int bits, int newValue) {
	int mask = (1 << bits) - 1; // e.g. 1 becomes 0001, 2 becomes 0011, 3 becomes 0111

	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
}

void HWBreakpoint::SetConditionLen(int& len, int value) {
	if (value == 1)
		len = 0;
	if (value == 2)
		len = 1;
	if (value == 4)
		len = 3;
	if (value == 8)
		len = 2;
}

bool HWBreakpoint::Set(void* address, int size, Condition when) {
	std::lock_guard<std::mutex> lock1(controlMutex);
	if (!initialized)
		HWBreakpoint::Init();

	std::unique_lock<std::mutex> lock2(workerMutex);

	int index = -1;

	// search for this address
	for (int i = 0; i < 4; ++i) {
		if (addresses[i] == address)
			index = i;
	}

	// find avalible place
	for (int i = 0; index < 0 && i < 4; ++i) {
		if (addresses[i] == nullptr) {
			index = i;
		}
	}

	if (index >= 0) {
		addresses[index] = address;
		len[index] = size;
		conditions[index] = when;
		SetForThreads(lock2);
		return true;
	}

	return false;
}

void HWBreakpoint::Clear(void* address) {
	std::lock_guard<std::mutex> lock1(controlMutex);
	if (!initialized)
		return;

	std::unique_lock<std::mutex> lock2(workerMutex);
	for (int index = 0; index < 4; ++index) {
		if (addresses[index] == address) {
			addresses[index] = nullptr;
			HWBreakpoint::SetForThreads(lock2);
		}
	}
}

void HWBreakpoint::ClearAll() {
	std::lock_guard<std::mutex> lock(controlMutex);
	if (!initialized)
		return;

	HWBreakpoint::Terminate();
}

void HWBreakpoint::Init() {
	if (initialized)
		return;

	std::memset(addresses, 0, sizeof(addresses));

	workerStop = true;
	workerThread = std::thread(HWBreakpoint::WorkerThreadProc);
	std::unique_lock<std::mutex> lock(workerMutex);
	workerSignal.wait(lock, [] { return !workerStop; });
	HWBreakpoint::BuildTrampoline();

	initialized = true;
}

void HWBreakpoint::Terminate() {
	if (!initialized)
		return;

	workerStop = true;
	workerSignal.notify_one();
	workerThread.join();

	initialized = false;
}

uint32_t cmpPtr = 0x0, threadStartJmpBack = 0x0;
__declspec(naked) void threadStartHook() { // our simple detour to get new threads
	_asm {
		cmp dword ptr ds : [cmpPtr] , 0x0;
		pushad;

		call HWBreakpoint::ThreadDeutor;

		popad;
		jmp threadStartJmpBack;
	}
}

void HWBreakpoint::BuildTrampoline() {
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
	if (!ntdllModule)
		return;

	uint32_t rtlThreadStartAddress = (uint32_t)GetProcAddress(ntdllModule, "RtlUserThreadStart");
	if (rtlThreadStartAddress == NULL) {
		printf("[HWBREAKPOINT] Fail to build trampoline. No method 'RtlUserThreadStart'.\n");
		return;
	}

	// simple hook, but before copy  the address for cmp condition
	DWORD dwOldProtect, dwNewProtect;
	Ntdll::NtProtectVirtualMemory((void*)rtlThreadStartAddress, 6, PAGE_EXECUTE_READ, (unsigned int*)&dwOldProtect);
	cmpPtr = *((uint32_t*)(rtlThreadStartAddress + 2));
	Ntdll::NtProtectVirtualMemory((void*)rtlThreadStartAddress, 6, dwOldProtect, (unsigned int*)&dwNewProtect);

	// hook it
	HookJMP((DWORD)rtlThreadStartAddress, (DWORD)threadStartHook);
	Nop((DWORD)(rtlThreadStartAddress + 5), 2);

	// set jmp back
	threadStartJmpBack = (uint32_t)(rtlThreadStartAddress + 7);
}

void HWBreakpoint::ThreadDeutor() {
	std::unique_lock<std::mutex> lock(workerMutex);

	pendingThread = GetCurrentThreadId();
	//printf("New thread started %d\n", pendingThread);
	workerSignal.notify_one();
	workerSignal.wait(lock, [] { return pendingThread == -1; });
}

void HWBreakpoint::ThreadDetourExternal(DWORD threadId) {
	if (!initialized)
		return;

	std::unique_lock<std::mutex> lock(workerMutex);

	pendingThread = threadId;
	//printf("Registering external thread %d\n", pendingThread);
	workerSignal.notify_one();
	workerSignal.wait(lock, [] { return pendingThread == -1; });
}

void HWBreakpoint::SetForThreads(std::unique_lock<std::mutex>& lock) {
	const DWORD pid = GetCurrentProcessId();

	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return;

	te32.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(hThreadSnap, &te32)) {
		CloseHandle(hThreadSnap);
		return;
	}

	do {
		if (te32.th32OwnerProcessID == pid) {
			pendingThread = te32.th32ThreadID;
			workerSignal.notify_one();
			workerSignal.wait(lock, [] { return pendingThread == -1; });
		}
	} while (Thread32Next(hThreadSnap, &te32));
}

void HWBreakpoint::RegisterThread(DWORD tid) {
	// this function supposed to be called only from worker thread
	if (GetCurrentThreadId() == tid)
		return;

	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
	if (!hThread)
		return;

	do {
		CONTEXT cxt;
		cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (SuspendThread(hThread) == -1)
			break;

		Bypass::ignoreNextThreadContextCall = true; // important to avoid protect drx
		if (Bypass::GetThreadContext()(hThread, &cxt) != 0)
			break;
		Bypass::ignoreNextThreadContextCall = false;

		for (int index = 0; index < 4; ++index) {
			const bool isSet = addresses[index] != nullptr;
			HWBreakpoint::SetBits(cxt.Dr7, index * 2, 1, isSet);

			if (isSet) {
				switch (index) {
				case 0: cxt.Dr0 = (DWORD_PTR)addresses[index]; break;
				case 1: cxt.Dr1 = (DWORD_PTR)addresses[index]; break;
				case 2: cxt.Dr2 = (DWORD_PTR)addresses[index]; break;
				case 3: cxt.Dr3 = (DWORD_PTR)addresses[index]; break;
				}

				int le = 0;
				HWBreakpoint::SetConditionLen(le, len[index]);

				HWBreakpoint::SetBits(cxt.Dr7, 16 + (index * 4), 2, (int)conditions[index]);
				HWBreakpoint::SetBits(cxt.Dr7, 18 + (index * 4), 2, (int)le);
			} else {
				switch (index) {
				case 0: cxt.Dr0 = 0; break;
				case 1: cxt.Dr1 = 0; break;
				case 2: cxt.Dr2 = 0; break;
				case 3: cxt.Dr3 = 0; break;
				}
			}
		}

		cxt.Dr6 = 0;

		if (Bypass::SetThreadContext()(hThread, &cxt) != 0)
			break;

		if (ResumeThread(hThread) == -1)
			break;
	} while (false);

	CloseHandle(hThread);
}

void HWBreakpoint::WorkerThreadProc() {
	pendingThread = -1;
	workerStop = false;
	workerSignal.notify_one();

	while (true) {
		std::unique_lock<std::mutex> lock(workerMutex);
		workerSignal.wait(lock, [] { return pendingThread != -1 || workerStop; });
		if (workerStop)
			return;

		if (pendingThread != -1) {
			HWBreakpoint::RegisterThread(pendingThread);
			pendingThread = -1;
			workerSignal.notify_one();
		}
	}
}