#include "pch.h"
#include "hook.h"
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include "ntdll.h"

#define STATUS_SUCCESS 0

void HookJMP(DWORD dwAddress, DWORD dwFunction)
{
	DWORD dwOldProtect, dwNewProtect, dwNewCall;
	dwNewCall = dwFunction - dwAddress - 5;
	Ntdll::NtProtectVirtualMemory((void*)dwAddress, 5, PAGE_EXECUTE_READWRITE, (unsigned int*)&dwOldProtect);
	//VirtualProtect((LPVOID)(dwAddress), 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(BYTE*)dwAddress = 0xE9;
	*(DWORD*)(dwAddress + 1) = dwNewCall;
	//VirtualProtect((LPVOID)(dwAddress), 5, dwOldProtect, &dwNewProtect);
	Ntdll::NtProtectVirtualMemory((void*)dwAddress, 5, dwOldProtect, (unsigned int*)&dwNewProtect);
}

void Nop(DWORD dwAddress, int size)
{
	DWORD dwOldProtect, dwNewProtect;
	Ntdll::NtProtectVirtualMemory((void*)dwAddress, size, PAGE_EXECUTE_READWRITE, (unsigned int*)&dwOldProtect);
	memset((void*)dwAddress, 0x90, size);
	Ntdll::NtProtectVirtualMemory((void*)dwAddress, size, dwOldProtect, (unsigned int*)&dwNewProtect);
}

void HookCall(DWORD dwAddress, DWORD dwFunction)
{
	DWORD dwOldProtect, dwNewProtect, dwNewCall;
	dwNewCall = dwFunction - dwAddress - 5;
	VirtualProtect((LPVOID)(dwAddress), 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(BYTE*)dwAddress = 0xE8;
	*(DWORD*)(dwAddress + 1) = dwNewCall;
	VirtualProtect((LPVOID)(dwAddress), 5, dwOldProtect, &dwNewProtect);
}

void HookCallN(DWORD dwAddress, DWORD dwFunction)
{
	DWORD dwOldProtect, dwNewProtect, dwNewCall;
	dwNewCall = dwFunction - dwAddress - 5;
	VirtualProtect((LPVOID)(dwAddress), 6, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(BYTE*)dwAddress = 0xE8;
	*(DWORD*)(dwAddress + 1) = dwNewCall;
	*(BYTE*)(dwAddress + 5) = 0x90;
	VirtualProtect((LPVOID)(dwAddress), 6, dwOldProtect, &dwNewProtect);
}

void OverWriteByte(DWORD addressToOverWrite, BYTE newValue)
{
	DWORD dwOldProtect, dwNewProtect;
	VirtualProtect((LPVOID)(addressToOverWrite), 1, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(BYTE*)addressToOverWrite = newValue;
	VirtualProtect((LPVOID)(addressToOverWrite), 1, dwOldProtect, &dwNewProtect);
}

void OverWriteWord(DWORD addressToOverWrite, WORD newValue)
{
	DWORD dwOldProtect, dwNewProtect;
	VirtualProtect((LPVOID)(addressToOverWrite), 2, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(WORD*)addressToOverWrite = newValue;
	VirtualProtect((LPVOID)(addressToOverWrite), 2, dwOldProtect, &dwNewProtect);
}

void OverWrite(DWORD addressToOverWrite, DWORD newValue)
{
	DWORD dwOldProtect, dwNewProtect;
	VirtualProtect((LPVOID)(addressToOverWrite), 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(DWORD*)addressToOverWrite = newValue;
	VirtualProtect((LPVOID)(addressToOverWrite), 4, dwOldProtect, &dwNewProtect);
}

void OverWriteBytes(DWORD addressToOverWrite, uint8_t* bytes, int bytesCount) {
	DWORD dwOldProtect, dwNewProtect;
	VirtualProtect((LPVOID)(addressToOverWrite), bytesCount, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy((void*)addressToOverWrite, bytes, bytesCount);
	VirtualProtect((LPVOID)(addressToOverWrite), bytesCount, dwOldProtect, &dwNewProtect);
}