#pragma once
#ifndef HWBREAKPOINT_H
#define HWBREAKPOINT_H
#include "ntdll.h"
#include "hook.h"
#include "bypass.h"
#include <iostream>
#include <mutex>
#include <tlhelp32.h>

class HWBreakpoint {
public:
	static enum class Condition {
		Execute = 0,
		Write = 1,
		ReadWrite = 3
	};

	static inline void SetBits(ULONG_PTR& dw, int lowBit, int bits, int newValue);
	static void SetConditionLen(int& len, int value);
	static bool Set(void* address, int size, Condition when);
	static void Clear(void* address);
	static void ClearAll();
	static void ThreadDetourExternal(DWORD threadId);
	static void Init();
	static void Terminate();
	static void BuildTrampoline();
	static void ThreadDeutor();
	static void SetForThreads(std::unique_lock<std::mutex>& lock);
	static void RegisterThread(DWORD tid);
	static void WorkerThreadProc();

	static bool ignoreNextThreadContextCall;
};
#endif