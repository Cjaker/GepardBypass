#pragma once
#ifndef NTDLL_H
#define NTDLL_H
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <map>
#include <string>

class Ntdll {
public:
	// Credits for some guy from Guidedhacking
	template<typename T>
	static T GetNtFunction(const char* szFunction) {
		// Initialise static handle to NtDll
		static HMODULE hNtDll = nullptr;

		// Get handle if still nullptr
		if (!hNtDll) hNtDll = GetModuleHandleA("ntdll.dll");

		// Return pointer to function
		if (hNtDll) return reinterpret_cast<T>(GetProcAddress(hNtDll, szFunction));
		else return nullptr;
	}

	static LONG NtProtectVirtualMemory(HANDLE hProcess, void* pAddress, unsigned int dwSize, unsigned int dwNewProtect, unsigned int* dwOldProtect) {
		// Type definition: https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtProtectVirtualMemory.html
		typedef LONG(WINAPI* tNtFunction)(
			IN      HANDLE  ProcessHandle,
			IN OUT  PVOID* BaseAddress,
			IN OUT  PULONG  NumberOfBytesToProtect,
			IN      ULONG   NewAccessProtection,
			OUT     PULONG  OldAccessProtection
			);

		// Get function pointer for NtProtectVirtualMemory
		static tNtFunction NtFunction = nullptr;
		if (!NtFunction) NtFunction = GetNtFunction<tNtFunction>("NtProtectVirtualMemory");

		// Align address and size pointers
		void* _pAddress = reinterpret_cast<void*>(pAddress);
		unsigned int _dwSize = dwSize;
		auto    pAddressAligned = _pAddress;
		auto    dwSizeAligned = _dwSize;

		// Cast variables to correct types to call function
		HANDLE  ProcessHandle = hProcess;
		PVOID* BaseAddress = reinterpret_cast<PVOID*>(&pAddressAligned);
		PULONG  NumberOfBytesToProtect = reinterpret_cast<PULONG>(&dwSizeAligned);
		ULONG   NewAccessProtection = static_cast<ULONG>(dwNewProtect);
		PULONG  OldAccessProtection = reinterpret_cast<PULONG>(dwOldProtect);

		// Return function call
		return NtFunction(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	}

	static LONG NtProtectVirtualMemory(void* pAddress, unsigned int dwSize, unsigned int dwNewProtect, unsigned int* dwOldProtect) {
		// Set process handle to -1 (use if internal)
		HANDLE hProcess = reinterpret_cast<HANDLE>(-1);

		// Return function call from main function
		return NtProtectVirtualMemory(hProcess, pAddress, dwSize, dwNewProtect, dwOldProtect);
	}

	static std::map<uint32_t, std::string> GetNtdllSyscalls();
};

#endif