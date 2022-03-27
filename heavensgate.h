#pragma once
#ifndef HEAVENS_GATE_H
#define HEAVENS_GATE_H
#include "patternscan.h"
#include "bypass.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <map>
#include <winternl.h>

class HeavensGate {
public:
	static bool PrepHeavensGate();
	static bool PatchHeavensGate(LPVOID GateAddress, void* Buffer, const std::size_t Size);
	static bool HookHeavensGate();
	static void DumpSyscallLogs();
	static bool logEnabled;

#if SYSCALL_LOG
	static std::map<uint32_t, int> syscallLog;
	static uint32_t syscallOrder[5000000];
	static uint32_t syscallArg[5000000];
#endif
};

#endif