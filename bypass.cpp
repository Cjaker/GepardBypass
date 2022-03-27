#include "pch.h"
#include "bypass.h"
#include "detours.h"
#include "ntdll.h"
#include "winapi.h"
#include "hwbreakpoint.h"
#include "heavensgate.h"

std::map<uint32_t, std::string> Bypass::syscallMap;
DWORD KiUserExceptionDispatcherNtdll = 0;

using pNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle,
	PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

HMODULE hNtdll = NULL;
HMODULE hKernel32 = NULL;
HMODULE hKernelBase = NULL;

void* ntExceptionDispatcherOrig;
void* kernelFreeConsole;
void* kiUserExceptionDispatcher;
void* rtlUnhandledExceptionFilter2;

__NtGetContextThread__ ntGetContextThreadOrig = nullptr;
__NtSetContextThread__ ntSetContextThreadOrig = nullptr;
__NtContinue__ ntContinueOrig = nullptr;
__NtYieldExecution__ ntYieldExecutionOrig = nullptr;
__NtSetInformationThread__ ntSetInformationThreadOrig = nullptr;
__NtQueryInformationThread__ ntQueryInformationThreadOrig = nullptr;
__NtRaiseException__ ntRaiseExceptionOrig = nullptr;
__KernelBaseSetUnhandledExceptionFilter__ kernelBaseSetUnhandledExceptionFilter = nullptr;
__NtProtectVirtualMemory__ ntProtectVirtualMemory = nullptr;
__NtQueryInformationProcess__ ntQueryInformationProcess = nullptr;
pNtWriteVirtualMemory NtWriteVirtualMemory = nullptr;
__RtlDispatchException RtlDispatchException = nullptr;
__RtlCaptureContext RtlCaptureContextOrig = nullptr;
__NtReadVirtualMemory NtReadVirtualMemoryOrig = nullptr;
//__RtlSetUnhandledExceptionFilter__ rtlSetUnhandledExceptionFilterOrig = nullptr;

bool IsEnabledTracing = false;
bool Bypass::ignoreNextThreadContextCall = false;

uint32_t gameSectionAddr = 0x401000;
uint32_t gameSectionSize = 0x81D000;
uint32_t fakeSectionAddr = 0x0;
unsigned char* fakeGameSectionBinary = nullptr;

void BackupGameSection() {
	// alloc fake section array
	fakeGameSectionBinary = new unsigned char[gameSectionSize];

	// virtual protect and copy
	DWORD dwOldProtect, dwNewProtect;
	Ntdll::NtProtectVirtualMemory((void*)gameSectionAddr, gameSectionSize, PAGE_EXECUTE_READWRITE, (unsigned int*)&dwOldProtect);
	memcpy(fakeGameSectionBinary, (void*)gameSectionAddr, gameSectionSize);
	Ntdll::NtProtectVirtualMemory((void*)gameSectionAddr, gameSectionSize, dwOldProtect, (unsigned int*)&dwNewProtect);
}

CHAR BinkwBuffer[200000];
DWORD BinkwLength = 0;
void GetCleanBinkwBinary() { // bypass for hashing our modified dll, make an original copy and use it
	HANDLE file = CreateFileA("C:\\binkw32.dll", GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	ReadFile(file, &BinkwBuffer[0], 200000, &BinkwLength, 0);
	CloseHandle(file);
}

void Bypass::Initialize() {
	hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll)
		return;

	hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
		return;

	hKernelBase = GetModuleHandleA("kernelbase.dll");
	if (!hKernelBase)
		return;

	ntQueryInformationProcess = (__NtQueryInformationProcess__)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	ntGetContextThreadOrig = (__NtGetContextThread__)GetProcAddress(hNtdll, "NtGetContextThread");
	ntSetContextThreadOrig = (__NtSetContextThread__)GetProcAddress(hNtdll, "ZwSetContextThread");
	ntContinueOrig = (__NtContinue__)GetProcAddress(hNtdll, "NtContinue");
	ntYieldExecutionOrig = (__NtYieldExecution__)GetProcAddress(hNtdll, "NtYieldExecution");
	ntSetInformationThreadOrig = (__NtSetInformationThread__)GetProcAddress(hNtdll, "NtSetInformationThread");
	ntQueryInformationThreadOrig = (__NtQueryInformationThread__)GetProcAddress(hNtdll, "ZwQueryInformationThread");
	ntRaiseExceptionOrig = (__NtRaiseException__)GetProcAddress(hNtdll, "NtRaiseException");
	kernelBaseSetUnhandledExceptionFilter = (__KernelBaseSetUnhandledExceptionFilter__)GetProcAddress(hKernelBase, "SetUnhandledExceptionFilter");
	kiUserExceptionDispatcher = GetProcAddress(hNtdll, "KiUserExceptionDispatcher");
	KiUserExceptionDispatcherNtdll = (DWORD)kiUserExceptionDispatcher;
	rtlUnhandledExceptionFilter2 = GetProcAddress(hNtdll, "RtlUnhandledExceptionFilter2");
	ntProtectVirtualMemory = (__NtProtectVirtualMemory__)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	kernelFreeConsole = (void*)GetProcAddress(hKernel32, "FreeConsole");
	RtlCaptureContextOrig = (__RtlCaptureContext)GetProcAddress(hNtdll, "RtlCaptureContext");
	NtReadVirtualMemoryOrig = (__NtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");

	uint32_t ntdllBaseAddr = WinApi::GetModuleBaseAddress(GetCurrentProcessId(), L"ntdll.dll");

	// scan pattern for searchin rtldispatch
	const char* pattern = "\x8B\xFF\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x7C\xA1\x00\x00\x00\x00\x33\xC4\x89\x44\x24\x78\x8B\x55\x0C\x53\x56\x8B\x75\x08\x33\xDB";
	const char* mask = "xxxxxxxxxxxx????xxxxxxxxxxxxxxxx";
	const WCHAR* ntdllModuleName = L"ntdll.dll";
	void* patternResult = PatternScan::ExternalModuleScan(GetCurrentProcess(), GetCurrentProcessId(), (wchar_t*)ntdllModuleName, (char*)pattern, (char*)mask);
	if (!patternResult) {
		printf("[PatternSearch] Failed to find RtlDispatchException!\n");
		return;
	}

	RtlDispatchException = (__RtlDispatchException)patternResult;
	Bypass::syscallMap = Ntdll::GetNtdllSyscalls();
	printf("[Wow64] Got %d ntdll functions.\n", Bypass::syscallMap.size());
	//BackupGameSection();
	GetCleanBinkwBinary();
}

void Bypass::Wow64Hook() {
	// initialize heavens gate hook
	if (HeavensGate::PrepHeavensGate()) // prep the gate
		if (!HeavensGate::HookHeavensGate()) // did we prep the gate? hook that bitch.
			return; // it failed smh

	printf("[Wow64] Heavens Gate hooked.\n");
}

void Bypass::WaitAndLogSyscall() {
	HeavensGate::logEnabled = true;
	Threading::Sleep(40000);
	HeavensGate::logEnabled = false;
	Threading::Sleep(3000);

	// log map
	HeavensGate::DumpSyscallLogs();
}

void Bypass::NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength, int ntStatus) {
	//printf("[NtQuerySystemInformation] Ret: %d Class: %d\n", ntStatus, (uint32_t)SystemInformationClass);
	if (SystemProcessInformation == SystemInformationClass && ntStatus == STATUS_SUCCESS) {
		//printf("[NtQuerySystemInformation] Checking processes\n");
		PNT_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
		PNT_SYSTEM_PROCESS_INFORMATION pNext = reinterpret_cast<PNT_SYSTEM_PROCESS_INFORMATION>(SystemInformation);

		do {
			pCurrent = pNext;
			pNext = reinterpret_cast<PNT_SYSTEM_PROCESS_INFORMATION>(reinterpret_cast<PUCHAR>(pCurrent) + pCurrent->NextEntryOffset);
			if (!wcsncmp(pNext->ImageName.Buffer, L"Procmon64.exe", pNext->ImageName.Length) ||
				!wcsncmp(pNext->ImageName.Buffer, L"ProcessHacker.exe", pNext->ImageName.Length)) { // tested and works
				std::wcout << "[NtQuerySystemInformation] Hiding process " << pNext->ImageName.Buffer << "\n";
				if (!pNext->NextEntryOffset) {
					pCurrent->NextEntryOffset = 0;
				} else {
					pCurrent->NextEntryOffset += pNext->NextEntryOffset;
				}
				pNext = pCurrent;
			}
		} while (pCurrent->NextEntryOffset != 0);
	} else if (0x16 == SystemInformationClass && ntStatus == STATUS_SUCCESS) { // pool, i don't remember well
	} else if ((0x0B == SystemInformationClass || 77 == SystemInformationClass) && ntStatus == STATUS_SUCCESS) { // drivers?
	}
}

void Bypass::HkNtOpenFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions,
	int& ntOpenFileRetValue) {
	/*std::wcout << "Hmm" << std::endl;
	if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
		std::wcout << "NtOpenFile: " << ObjectAttributes->ObjectName->Buffer << std::endl;
	}*/
}

void Bypass::HkNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, int& ntDeviceIoControlFileValue) {
	if (IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY) {
		PSTORAGE_PROPERTY_QUERY query = PSTORAGE_PROPERTY_QUERY(InputBuffer);
		if (query && query->PropertyId == StorageDeviceProperty) {
			if (OutputBufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
				PSTORAGE_DEVICE_DESCRIPTOR deviceDescriptor = PSTORAGE_DEVICE_DESCRIPTOR(OutputBuffer);
				if (deviceDescriptor) {
					if (deviceDescriptor->SerialNumberOffset) {
						auto serial = PCHAR(deviceDescriptor) + deviceDescriptor->SerialNumberOffset;
						memset(serial, 0, strlen(serial));
						strcpy(serial, "6959B950");
						std::cout << "[Spoofer & AntiVM] New disk serial " << serial << std::endl;
					}

					if (deviceDescriptor->ProductIdOffset) {
						auto productId = PCHAR(deviceDescriptor) + deviceDescriptor->ProductIdOffset;
						memset(productId, 0, strlen(productId));
						strcpy(productId, "NSA SSD Disk");
						std::cout << "[Spoofer & AntiVM] New disk model " << productId << std::endl;
					}
				}
			}
		}
	} else if (IoControlCode == IOCTL_DISK_GET_LENGTH_INFO) { // anti-vm bypass
		// bypass volume disk size
		if (OutputBuffer) {
			PGET_LENGTH_INFORMATION lenInformation = PGET_LENGTH_INFORMATION(OutputBuffer);
			lenInformation->Length.QuadPart = 137438953472; // 128 GB
			lenInformation->Length.LowPart = (DWORD)0; // 128 GB
			lenInformation->Length.HighPart = (LONG)32; // 128 GB
			std::cout << "[AntiVM] New HardDisk size: " << lenInformation->Length.QuadPart << std::endl;
		}
	}
}

void Bypass::EraseHeaders(HINSTANCE hModule) {
	/*
	* just a func to erase headers by Croner.
	* keep in mind you wont be able to load
	* any resources after you erase headers.
	*/
	PIMAGE_DOS_HEADER pDoH;
	PIMAGE_NT_HEADERS pNtH;
	DWORD i, ersize, protect;
	if (!hModule) return;

	// well just to make clear what we doing
	pDoH = (PIMAGE_DOS_HEADER)(hModule);
	pNtH = (PIMAGE_NT_HEADERS)((LONG)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	ersize = sizeof(IMAGE_DOS_HEADER);
	if (Ntdll::NtProtectVirtualMemory((void*)pDoH, (unsigned int)ersize, (unsigned int)PAGE_READWRITE, (unsigned int*)&protect)) {
		for (i = 0; i < ersize; i++)
			*(BYTE*)((BYTE*)pDoH + i) = 0;
	}
	ersize = sizeof(IMAGE_NT_HEADERS);
	if (pNtH && Ntdll::NtProtectVirtualMemory((void*)pNtH, (unsigned int)ersize, (unsigned int)PAGE_READWRITE, (unsigned int*)&protect)) {
		for (i = 0; i < ersize; i++)
			*(BYTE*)((BYTE*)pNtH + i) = 0;
	}
	return;
}

WCHAR tmpProcessModule[MAX_PATH];
void Bypass::UnlinkModule(const wchar_t* dllName) {
	_NNPROCESS_BASIC_INFORMATION processBasicInformation;
	ULONG size;
	ntQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &size);
	NNPEB* pPeb = processBasicInformation.PebBaseAddress;

	for (auto entry = pPeb->Ldr->InMemoryOrderModuleList.Flink; entry != &pPeb->Ldr->InMemoryOrderModuleList; entry = entry->Flink) {
		_LDR_DATA_TABLE_ENTRY* pCurEntry = (_LDR_DATA_TABLE_ENTRY*)entry;

		for (int index = 0; index < pCurEntry->FullDllName.Length; index++)
			tmpProcessModule[index] = towlower(pCurEntry->FullDllName.Buffer[index]);

		tmpProcessModule[pCurEntry->FullDllName.Length] = '\0';

		if (!wcscmp(tmpProcessModule, dllName)) {
			entry->Flink->Blink = entry->Blink;
			entry->Blink->Flink = entry->Flink;
		}
	}

	for (auto entry = pPeb->Ldr->InLoadOrderModuleList.Flink; entry != &pPeb->Ldr->InLoadOrderModuleList; entry = entry->Flink) {
		_LDR_DATA_TABLE_ENTRY* pCurEntry = (_LDR_DATA_TABLE_ENTRY*)entry;

		for (int index = 0; index < pCurEntry->FullDllName.Length; index++)
			tmpProcessModule[index] = towlower(pCurEntry->FullDllName.Buffer[index]);

		tmpProcessModule[pCurEntry->FullDllName.Length] = '\0';

		if (!wcscmp(tmpProcessModule, dllName)) {
			entry->Flink->Blink = entry->Blink;
			entry->Blink->Flink = entry->Flink;
		}
	}
}

WCHAR tmpProcessName[MAX_PATH];
void Bypass::NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength, int& retValue) {
	if (retValue == STATUS_SUCCESS && ProcessInformationClass == PROCESSINFOCLASS::ProcessBasicInformation) { // hide module
		//PROCESS_BASIC_INFORMATION* procBasicInfo = (PROCESS_BASIC_INFORMATION*)ProcessInformation;
		//PEB procPeb = { 0 };
		//SIZE_T ulBytesRead = 0;
		//NTSTATUS status = NtReadVirtualMemoryOrig(ProcessHandle, (LPVOID)procBasicInfo->PebBaseAddress, &procPeb, sizeof(PEB), &ulBytesRead);
		//if (status != STATUS_SUCCESS) {
		//	// can't get Peb base addr
		//	return;
		//}

		//NPEB_LDR_DATA pebLdrData = { 0 };
		//status = NtReadVirtualMemoryOrig(ProcessHandle, (LPVOID)procPeb.Ldr, &pebLdrData, sizeof(NPEB_LDR_DATA), &ulBytesRead);
		//if (status != STATUS_SUCCESS) {
		//	// can't read modules list
		//	return;
		//}

		//LIST_ENTRY* pLdrListHead = (LIST_ENTRY*)pebLdrData.InLoadOrderModuleList.Flink;
		//LIST_ENTRY* pLdrCurrentNode = pebLdrData.InLoadOrderModuleList.Flink;
		//NLDR_DATA_TABLE_ENTRY* previousEntry = (NLDR_DATA_TABLE_ENTRY*)pLdrCurrentNode;

		//do {
		//	NLDR_DATA_TABLE_ENTRY* lstEntry = (NLDR_DATA_TABLE_ENTRY*)pLdrCurrentNode;
		//	NLDR_DATA_TABLE_ENTRY* nextEntry = (NLDR_DATA_TABLE_ENTRY*)lstEntry->InLoadOrderLinks.Flink;
		//	if (lstEntry->BaseDllName.Length > 0) { // hide our module there
		//		for (int index = 0; index < lstEntry->BaseDllName.Length; index++)
		//			tmpProcessName[index] = lstEntry->BaseDllName.Buffer[index];

		//		tmpProcessName[lstEntry->BaseDllName.Length] = '\0';

		//		for (int i = 0; i < lstEntry->BaseDllName.Length; i++) // lowercase
		//			tmpProcessName[i] = towlower(tmpProcessName[i]);

		//		if (wcsstr(tmpProcessName, L"usern32.dll")) {
		//			// get next entry and replace previous flink
		//			if (!lstEntry->InLoadOrderLinks.Flink || lstEntry->InLoadOrderLinks.Flink == pLdrListHead) {
		//				//std::wcout << "a " << tmpProcessName << "\n";
		//				previousEntry->InLoadOrderLinks.Flink = pLdrListHead;
		//			} else {
		//				//std::wcout << "b " << nextEntry->InLoadOrderLinks.Blink << ", " << nextEntry->InLoadOrderLinks.Flink << "\n";
		//				previousEntry->InLoadOrderLinks.Flink = lstEntry->InLoadOrderLinks.Flink;
		//			}

		//			return;
		//		}
		//	}

		//	previousEntry = lstEntry;
		//	pLdrCurrentNode = lstEntry->InLoadOrderLinks.Flink;
		//} while (pLdrListHead != pLdrCurrentNode);
	}
}

HANDLE binkwHandle = 0;
void Bypass::HkNtCreateFile(PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength,
	int& ntCreateFileRetValue) {
	// to bypass it modify return with STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034)
	if (ObjectAttributes) {
		if (ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
			PWSTR objectName = ObjectAttributes->ObjectName->Buffer;
			//std::wcout << "Checking: " << ObjectAttributes->ObjectName->Buffer << std::endl;
			if (wcsstr(objectName, L"ProcmonDebugLogger") ||
				wcsstr(objectName, L"ProcmonExternalLogger") ||
				wcsstr(objectName, L"FltMgr")/*bypass user-mode flt for enumerating drivers*/) {
				// bypass it
				std::wcout << "[NtCreateFile] Patching " << ObjectAttributes->ObjectName->Buffer << std::endl;

				ntCreateFileRetValue = STATUS_OBJECT_NAME_NOT_FOUND;
				//return ntCreateFileRetValue;
			} else if (wcsstr(objectName, L"binkw32.dll")) {
				binkwHandle = *FileHandle;
			}
			//else if (wcsstr(objectName, L"PhysicalDrive0")) {
			//	std::wcout << "Bypassed: " << ObjectAttributes->ObjectName->Buffer << std::endl;
			//	ntCreateFileRetValue = 0xC0000022; // access denied
			//}
		}
	}
}

void Bypass::HkNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key, int& ntReadFileRetValue) {
	if (binkwHandle != 0 && FileHandle == binkwHandle && ntReadFileRetValue == 0) {
		binkwHandle = 0;
		// get length of received buffer
		if (IoStatusBlock->Information == 188416) {
			std::cout << "[NtReadFile] Patching buffer of binkw32 dll " << IoStatusBlock->Information << std::endl;
			IoStatusBlock->Information = BinkwLength;
			// fill buffer with fake one
			uint8_t* buffer = (uint8_t*)Buffer;
			for (int index = 0; index < BinkwLength; index++) {
				buffer[index] = BinkwBuffer[index];
			}
		}
	}
}

void Bypass::HkNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, int& ntQueryInformationFileRetValue) {
	if (binkwHandle != 0 && FileHandle == binkwHandle && ntQueryInformationFileRetValue == 0 && FileInformationClass == 5) { // 5 = standard information
		uint32_t fileInfoAddr = (uint32_t)FileInformation;
		_FILE_STANDARD_INFO* fileInfo = (_FILE_STANDARD_INFO*)FileInformation;
		/*192512, 0, 192512
		192512, 0, 192512*/
		std::cout << fileInfo->AllocationSize.QuadPart << ", " << fileInfo->AllocationSize.HighPart << ", " << fileInfo->AllocationSize.LowPart << std::endl;
		std::cout << fileInfo->EndOfFile.QuadPart << ", " << fileInfo->EndOfFile.HighPart << ", " << fileInfo->EndOfFile.LowPart << std::endl;
		if (fileInfo->AllocationSize.QuadPart == 192512) {
			fileInfo->AllocationSize.QuadPart = fileInfo->EndOfFile.QuadPart = fileInfo->AllocationSize.LowPart = fileInfo->EndOfFile.LowPart = BinkwLength;
			std::cout << "[NtQueryInformationFile] Patching file information of binkw32 dll " << BinkwLength << std::endl;
			//*((uint32_t*)(fileInfoAddr + 8)) = BinkwLength; //(length)
		}
	}
}

// DRx functions
void Bypass::NtGetContextThreadSysCall(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
	DWORD ContextBackup = 0;
	BOOLEAN DebugRegistersRequested = FALSE;
	if (ThreadHandle == GetCurrentThread() || HandleToULong(GetCurrentProcessId()) == Threading::GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
	{
		if (ThreadContext) {
			ContextBackup = ThreadContext->ContextFlags;
			ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
			DebugRegistersRequested = ThreadContext->ContextFlags != ContextBackup;
		}
	}

	if (ContextBackup) {
		ThreadContext->ContextFlags = ContextBackup;
		if (DebugRegistersRequested) {
			Threading::ClearThreadContext(ThreadContext);
#ifdef _WIN64
			ThreadContext->LastBranchToRip = 0;
			ThreadContext->LastBranchFromRip = 0;
			ThreadContext->LastExceptionToRip = 0;
			ThreadContext->LastExceptionFromRip = 0;
#endif
		}
	}
}

NTSTATUS NTAPI __NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
	DWORD ContextBackup = 0;
	if (ThreadHandle == GetCurrentThread() || HandleToULong(GetCurrentProcessId()) == Threading::GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
	{
		if (ThreadContext) {
			ContextBackup = ThreadContext->ContextFlags;
			ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
		}
	}

	NTSTATUS ntStat = ntGetContextThreadOrig(ThreadHandle, ThreadContext);

	if (ContextBackup) {
		ThreadContext->ContextFlags = ContextBackup;
	}

	return ntStat;
}

NTSTATUS NTAPI __NtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert) {
	DWORD_PTR retAddress = (DWORD_PTR)_ReturnAddress();
	DWORD kiAddr = (DWORD)KiUserExceptionDispatcherNtdll;
	if (ThreadContext != nullptr &&
		retAddress >= kiAddr && retAddress < (kiAddr + 0x100)) {
		int index = Threading::ThreadDebugContextFindExistingSlotIndex();
		if (index != -1) {
			Threading::ThreadRetrieveSavedContext(ThreadContext, index);
			Threading::ThreadDebugContextRemoveEntry(index);
		}
	}

	return ntContinueOrig(ThreadContext, RaiseAlert);
}

void NTAPI HandleKiUserExceptionDispatcher(PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame) {
	ExceptionHandler::MainExceptionHandler(pExcptRec, ContextFrame);

	// protect DRX
	if (ContextFrame && (ContextFrame->ContextFlags & CONTEXT_DEBUG_REGISTERS)) {
		int slotIndex = Threading::ThreadDebugContextFindFreeSlotIndex();
		if (slotIndex != -1) {
			Threading::ThreadDebugContextSaveContext(slotIndex, ContextFrame);
		}

		Threading::ClearThreadContext(ContextFrame);
	}
}

__declspec(naked) void NTAPI HookedKiUserExceptionDispatcher()// (PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame) //remove DRx Registers
{
	//MOV ECX,DWORD PTR SS:[ESP+4] <- ContextFrame
	//MOV EBX,DWORD PTR SS:[ESP] <- pExcptRec
	__asm
	{
		MOV EAX, [ESP + 4]
		MOV ECX, [ESP]
		PUSH EAX
		PUSH ECX
		CALL HandleKiUserExceptionDispatcher
		jmp kiUserExceptionDispatcher
	}
}

NTSTATUS NTAPI __NtYieldExecution() {
	return STATUS_NO_YIELD_PERFORMED;
}

BYTE originalKiUserCode[] = { 0x83, 0x3D, 0xA0, 0x69, 0xD5, 0x77, 0x00 };
BYTE originalRtlUnhandledExceptionFilter2[] = { 0x6A, 0x18, 0x68, 0xF0, 0xD4, 0xD3, 0x77 };
NTSTATUS NTAPI __NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
	//printf("[__NtProtectVirtualMemory] Called. Protecting virtual memory at %#010x flag %lu size %lu\n", (uint32_t)(*BaseAddress), NewAccessProtection, *NumberOfBytesToProtect);
	if (*BaseAddress == kiUserExceptionDispatcher && *NumberOfBytesToProtect == 7 && NewAccessProtection == PAGE_EXECUTE_READ) {
		// patch this shit out dude
		memcpy((void*)(*BaseAddress), originalKiUserCode, 7);
		printf("[__NtProtectVirtualMemory] Removed KiUser hook\n");
	} else if (*BaseAddress == rtlUnhandledExceptionFilter2 && *NumberOfBytesToProtect == 7 && NewAccessProtection == PAGE_EXECUTE_READ) {
		memcpy((void*)(*BaseAddress), originalRtlUnhandledExceptionFilter2, 7);
		printf("[__NtProtectVirtualMemory] Removed rtlUnhandledExceptionFilter2 hook\n");
	}

	return ntProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

NTSTATUS NTAPI __NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
	// Ignore the call with ThreadHideFromDebugger flag
	//printf("[__NtSetInformationThread] Called %#010x\n", ThreadInformationClass);
	if (ThreadInformationClass == 0x11 && (int)ThreadInformation <= NULL && ThreadInformationLength <= NULL) {
		DWORD threadId = GetThreadId(ThreadHandle);
		printf("[__NtSetInformationThread][%d] Bypass ThreadHideFromDebugger.\n", threadId);
		HWBreakpoint::ThreadDetourExternal(threadId); // update hwbp on this thread
		return STATUS_SUCCESS;
	}
	return ntSetInformationThreadOrig(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

void RtlCaptureContextHook(PCONTEXT Context) {
	// call original method
	RtlCaptureContextOrig(Context);
}

char __stdcall RtlDispatchExceptionHook(_EXCEPTION_RECORD* a1, PCONTEXT Context) {
	printf("[RtlDispatchExceptionHook] Called %#010x\n", a1->ExceptionAddress);
	// handle by return 1, avoiding veh
	return 1;
}

LONG WINAPI CustomUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionPointers) {
	printf("[CustomUnhandledExceptionFilter] Handled some exception\n");
	return EXCEPTION_CONTINUE_EXECUTION;
}

uint32_t __stdcall __KernelBaseSetUnhandledExceptionFilter(DWORD TopLevelExceptionFilter) {
	printf("[SetUnhandledExceptionFilter] Got %#010x\n", TopLevelExceptionFilter);
	// set to our handler
	TopLevelExceptionFilter = (DWORD)CustomUnhandledExceptionFilter;
	kernelBaseSetUnhandledExceptionFilter(TopLevelExceptionFilter);

	printf("[SetUnhandledExceptionFilter] Setted another handler %#010x\n", TopLevelExceptionFilter);
	// return fake address of gepard handler
	return 0x6C6E26C0;
}

void Bypass::SetExceptionFilter(DWORD TopLevelExceptionFilter) { // replace exception filter (NULL will remove)
	kernelBaseSetUnhandledExceptionFilter(TopLevelExceptionFilter);
}

void Bypass::PatchFreeConsole() { // make it every call return 0 as failed, to AC think no console is allocated
	DWORD dwOldProtect, dwNewProtect, dwNewCall;
	DWORD addr = (DWORD)kernelFreeConsole;
	Ntdll::NtProtectVirtualMemory((void*)addr, 6, PAGE_EXECUTE_READWRITE, (unsigned int*)&dwOldProtect);
	*((BYTE*)addr) = 0x33;
	*((BYTE*)addr + 1) = 0xC0; // xor eax, eax
	*((BYTE*)addr + 2) = 0xC3; // ret
	memset((LPVOID)(addr + 3), 0x90, 3); // fill rest with nops
	Ntdll::NtProtectVirtualMemory((void*)addr, 6, dwOldProtect, (unsigned int*)&dwNewProtect);
}

void Bypass::SetKiUserCallback(uintptr_t handler) { // technique to use custom callback instead of main KiUser routine
	auto kiuserexceptiondispatcher = (uintptr_t)kiUserExceptionDispatcher;
	auto ptr = *(uintptr_t**)(kiuserexceptiondispatcher + 2); // LdrParentRtlInitializeNtUserPfn+0xC

	auto OrgKiUserExceptionDispatcher = kiuserexceptiondispatcher + 0x17;

	*ptr = handler;
}

void Bypass::PatchHooks() {
	// we will patch 2 hooks by gepard restoring the original code
	// update patches addresses
	uint32_t ntdllBaseAddr = WinApi::GetModuleBaseAddress(GetCurrentProcessId(), L"ntdll.dll");
	if (ntdllBaseAddr == 0) {
		printf("[PatchHooks] Failed to get ntdll module.\n");
		return;
	}

	// prepare offsets
	uint32_t kiUserOffset = 0x1269A0 + ntdllBaseAddr;
	uint32_t rtlUnhandledOffset = 0x10D5B0 + ntdllBaseAddr;

	// update from arrays
	// +2 = kiuser
	memcpy(&originalKiUserCode[2], &kiUserOffset, sizeof(uint32_t));
	memcpy(&originalRtlUnhandledExceptionFilter2[3], &rtlUnhandledOffset, sizeof(uint32_t));

	// hook protect virtual memory for tracking KiUserHook (only necessary if injected before gepard hooks)
	if (ntProtectVirtualMemory) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)ntProtectVirtualMemory, __NtProtectVirtualMemory);
		DetourTransactionCommit();
	}

	DWORD dwOldProtect, dwNewProtect;
	DWORD addr = (DWORD)kiUserExceptionDispatcher;
	Ntdll::NtProtectVirtualMemory((void*)addr, 7, PAGE_EXECUTE_READWRITE, (unsigned int*)&dwOldProtect);
	if (*((BYTE*)addr) == 0xE9) {
		// restore code
		memcpy((void*)addr, originalKiUserCode, 7);
	}
	Ntdll::NtProtectVirtualMemory((void*)addr, 7, dwOldProtect, (unsigned int*)&dwNewProtect);

	dwOldProtect = dwNewProtect = 0;
	addr = (DWORD)rtlUnhandledExceptionFilter2;
	Ntdll::NtProtectVirtualMemory((void*)addr, 7, PAGE_EXECUTE_READWRITE, (unsigned int*)&dwOldProtect);
	if (*((BYTE*)addr) == 0xE9) {
		// restore code
		memcpy((void*)addr, originalRtlUnhandledExceptionFilter2, 7);
	}
	Ntdll::NtProtectVirtualMemory((void*)addr, 7, dwOldProtect, (unsigned int*)&dwNewProtect);

	if (kiUserExceptionDispatcher) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)kiUserExceptionDispatcher, HookedKiUserExceptionDispatcher);
		DetourTransactionCommit();
	}

	if (RtlDispatchException) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)RtlDispatchException, RtlDispatchExceptionHook);
		DetourTransactionCommit();
	}
	// RtlCaptureContextOrig hold some thread context stuff
}

__NtGetContextThread__ Bypass::GetThreadContext() {
	return ntGetContextThreadOrig;
}

__NtSetContextThread__ Bypass::SetThreadContext() {
	return ntSetContextThreadOrig;
}

void Bypass::HideDRx() {
	if (ntSetContextThreadOrig) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)ntSetContextThreadOrig, __NtSetContextThread);
		DetourTransactionCommit();
	}
	if (ntContinueOrig) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)ntContinueOrig, __NtContinue);
		DetourTransactionCommit();
	}
	if (ntYieldExecutionOrig) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)ntYieldExecutionOrig, __NtYieldExecution);
		DetourTransactionCommit();
	}
	if (ntSetInformationThreadOrig) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)ntSetInformationThreadOrig, __NtSetInformationThread);
		DetourTransactionCommit();
	}
	// ntQueryInformationProcess hold some debugging info of process
	// ntQueryInformationThread hold thread context on class [0x1D = ThreadWow64Context]
	// ntRaiseException hold thread context info too
}
