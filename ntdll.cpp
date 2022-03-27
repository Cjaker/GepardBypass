#include "pch.h"
#include "ntdll.h"

std::map<uint32_t, std::string> Ntdll::GetNtdllSyscalls() {
	std::map<uint32_t, std::string> retSyscallMap;
	PIMAGE_DOS_HEADER peDosHeader;
	PIMAGE_NT_HEADERS peNtHeader;
	PIMAGE_EXPORT_DIRECTORY peExportDirectory;

	HMODULE hModule = GetModuleHandleA("ntdll.dll");
	if (!hModule) {
		return retSyscallMap;
	}

	peDosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (peDosHeader->e_magic != IMAGE_DOS_SIGNATURE) // ARE YOU A WIN32 APP RIGHT ? MZ Checking
	{
		return retSyscallMap;
	}

	peNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + peDosHeader->e_lfanew);
	if (peNtHeader->Signature != IMAGE_NT_SIGNATURE) // PE00
	{
		return retSyscallMap;
	}

	if (peNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) // you really don't have any exports u sonofbitch
	{
		return retSyscallMap;
	}

	peExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + peNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); // HEHEBOY
	PDWORD startFunctionsAddress = (PDWORD)((LPBYTE)hModule + peExportDirectory->AddressOfFunctions);
	PDWORD startFunctionsNameAddress = (PDWORD)((LPBYTE)hModule + peExportDirectory->AddressOfNames);
	PWORD startFunctionsOrdinalAddress = (PWORD)((LPBYTE)hModule + peExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < peExportDirectory->NumberOfFunctions; i++) {
		//printf("Function: %s\n", (char*)hModule + startFunctionsNameAddress[i]);
		uint32_t address = (uint32_t)((LPBYTE)hModule + startFunctionsAddress[startFunctionsOrdinalAddress[i]]);;
		// check if that is syscall
		uint8_t opcode = *((uint8_t*)address);
		if (opcode != 0xB8)
			continue;

		// get syscall
		uint32_t syscallId = *((uint32_t*)(address + 1));
		retSyscallMap.emplace(syscallId, std::string((char*)hModule + startFunctionsNameAddress[i]));
	}

	return retSyscallMap;
}
