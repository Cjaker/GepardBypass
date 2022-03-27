#include "pch.h"
#include "breakpoint.h"

// THIS CLASS ONLY SUPPORTS ONE BYTE INSTRUCTION
std::map<uint32_t, uint8_t> backupInstruction;
void Breakpoint::SetInt3(DWORD address) {
	DWORD dwOldProtect = 0;
	DWORD dwNewProtect = 0;
	Ntdll::NtProtectVirtualMemory((void*)address, 1, PAGE_EXECUTE_READWRITE, (unsigned int*)&dwOldProtect);

	if (*((BYTE*)address) == 0xCC) { // has int3, no need to change
		Ntdll::NtProtectVirtualMemory((void*)address, 1, dwOldProtect, (unsigned int*)&dwNewProtect);
		return;
	}

	backupInstruction[address] = *((BYTE*)address);
	*((BYTE*)address) = 0xCC;
	Ntdll::NtProtectVirtualMemory((void*)address, 1, dwOldProtect, (unsigned int*)&dwNewProtect);
}

void Breakpoint::ClearInt3(DWORD address) {
	DWORD dwOldProtect = 0;
	DWORD dwNewProtect = 0;
	Ntdll::NtProtectVirtualMemory((void*)address, 1, PAGE_EXECUTE_READWRITE, (unsigned int*)&dwOldProtect);

	if (*((BYTE*)address) != 0xCC) { // no int3 at address
		Ntdll::NtProtectVirtualMemory((void*)address, 1, dwOldProtect, (unsigned int*)&dwNewProtect);
		return;
	}

	// restore
	*((BYTE*)address) = backupInstruction[address];
	Ntdll::NtProtectVirtualMemory((void*)address, 1, dwOldProtect, (unsigned int*)&dwNewProtect);
}

int Breakpoint::GetOriginalInstruction(DWORD address) {
	auto it = backupInstruction.find(address);
	if (it == backupInstruction.end())
		return -1;

	return (int)it->second;
}
