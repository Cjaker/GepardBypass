#pragma once
#ifndef PATTERN_SCAN_H
#define PATTERN_SCAN_H
#include <Windows.h>
#include <TlHelp32.h>
#include "processtools.h"

class PatternScan {
public:
	//Internal Pattern Scan
	static void* InternalScan(char* base, size_t size, char* pattern, char* mask);

	//External Wrapper
	static void* ExternalScan(HANDLE hPRocess, uintptr_t begin, uintptr_t end, char* pattern, char* mask);

	//Module wrapper for external pattern scan
	static void* ExternalModuleScan(HANDLE hProcess, DWORD processID, wchar_t* module, char* pattern, char* mask);
};


#endif