#include "pch.h"
#include "heavensgate.h"

bool HeavensGate::logEnabled = false;
// SYSCALL_LOG not stable, avoid use it
#if SYSCALL_LOG
std::map<uint32_t, int> HeavensGate::syscallLog;
uint32_t HeavensGate::syscallOrder[5000000];
uint32_t HeavensGate::syscallArg[5000000];
#endif

namespace Ordinal {
	DWORD NtAllocateVirtualMemory = 0x0;
	DWORD NtGetContextThread = 0x0;
	DWORD NtOpenProcess = 0x0;
	DWORD NtCreateFile = 0x0;
	DWORD NtOpenFile = 0x0;
	DWORD NtReadFile = 0x0;
	DWORD NtQuerySystemInformation = 0x0;
	DWORD NtQuerySystemInformationEx = 0x0;
	DWORD NtPowerInformation = 0x0;
	DWORD NtOpenDirectoryObject = 0x0;
	DWORD NtQueryDirectoryObject = 0x0;
	DWORD NtWow64GetNativeSystemInformation = 0x0;
	DWORD NtQueryInformationProcess = 0x0;
	DWORD NtQueryInformationFile = 0x0;
	DWORD NtQueryDirectoryFileEx = 0x0;
	DWORD NtDeviceIoControlFile = 0x0;

	DWORD NtUserEnumDisplayDevices = 0x10EA; // win32u
}

namespace {
	void* NewHeavensGate = nullptr;
	void* MapReturnAddress = nullptr;
}

std::map<std::pair<void*, void*>, const char*> LogReturnAddr;
NTSTATUS NTAPI hkNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {
	// patch here
	if (!Bypass::ignoreNextThreadContextCall)
		Bypass::NtGetContextThreadSysCall(ThreadHandle, ThreadContext);
	// patch end

	// If you wanna check the actual returnvalue we got just grab eax via inline asm iirc.
	PVOID stackTrace[3] = { 0 };
	USHORT capturedFrames = 0;

	capturedFrames = RtlCaptureStackBackTrace(0, 3, stackTrace, NULL); // Capture the last 3 frames.
	capturedFrames = (capturedFrames) ? capturedFrames : RtlCaptureStackBackTrace(0, 3, stackTrace, NULL); // sometimes need to request stack again

	if (stackTrace[1] == MapReturnAddress) // is it LogReturnAddr allocating memory?
		return 0; // yes then just return dont add it to the map else we get a endless loop lol.

	LogReturnAddr.insert(std::make_pair(std::make_pair(stackTrace[1], stackTrace[2]), "NtGetContextThread")); // Push the returnaddress of the last 2 frames. Don't push the current one.
	// Just an example for the usage. You can log returnaddresses for further analyzing.

	return 0; // Make it fail with #define STATUS_INTERNAL_ERROR 0xC00000E5 if needed
}

int retValue = -1;
NTSTATUS __stdcall hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	_asm {
		mov retValue, eax;
	}

	//std::cout << "[NtQuerySystemInformation] Class [0x" << std::hex << SystemInformationClass << "]" << std::endl;

	PVOID stackTrace[3] = { 0 };
	USHORT capturedFrames = 0;

	capturedFrames = RtlCaptureStackBackTrace(0, 3, stackTrace, NULL); // Capture the last 3 frames.
	capturedFrames = (capturedFrames) ? capturedFrames : RtlCaptureStackBackTrace(0, 3, stackTrace, NULL); // sometimes need to request stack again

	HMODULE kernel32Module = GetModuleHandleA("kernel32.dll");
	if (!kernel32Module)
		return retValue;

	uint32_t heapSetInformationAddr = (uint32_t)GetProcAddress(kernel32Module, "HeapSetInformation");
	if (!heapSetInformationAddr)
		return retValue;

	if (retValue != 0) {
		uint32_t stackTraceRetAddr = (uint32_t)stackTrace[1];
		if (stackTraceRetAddr >= heapSetInformationAddr && stackTraceRetAddr <= heapSetInformationAddr + 0xF0 || retValue == 0xC0000004) {
			// return ret value and next time will be the real hook
			return retValue;
		}
	} else {
		// in that case, we got success so we can bypass
		Bypass::NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength, retValue);
		return 0;
	}
}

std::map<std::pair<void*, void*>, const char*> LogReturnAddrSystemInformationEx; // create another map maybe for future
int retValueSystemInformationEx = -1;
NTSTATUS __stdcall hkNtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength) {
	_asm {
		mov retValueSystemInformationEx, eax;
	}

	/*if (retValueSystemInformationEx == 0)
		std::cout << "[NtQuerySystemInformationEx] Class [0x" << std::hex << SystemInformationClass << "]" << std::endl;*/

	return retValueSystemInformationEx;
}

int retValuePowerInformation = -1;
NTSTATUS __stdcall hkNtPowerInformation(POWER_INFORMATION_LEVEL InformationLevel, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
	_asm {
		mov retValuePowerInformation, eax;
	}

	if (retValuePowerInformation == 0) {
		//printf("PWInfo Bypassing %d\n", InformationLevel);
		if (OutputBuffer && OutputBufferLength > 0) {
			std::cout << "[NtPowerInformation] Patched" << std::endl;
			PSYSTEM_POWER_CAPABILITIES pwCap = (PSYSTEM_POWER_CAPABILITIES)OutputBuffer;
			pwCap->SystemS1 = 1;
			pwCap->ThermalControl = 1;
		}
		return retValuePowerInformation;
	}

	return retValuePowerInformation;
}

int retValueOpenDirectoryObject = -1;
NTSTATUS __stdcall hkNtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
	_asm {
		mov retValueOpenDirectoryObject, eax;
	}

	std::wcout << "[NtOpenDirectoryObject] " << ObjectAttributes->ObjectName->Buffer << ", " << retValueOpenDirectoryObject << "\n";
	if (retValueOpenDirectoryObject == 0) {
		return retValueOpenDirectoryObject;
	}

	return retValueOpenDirectoryObject;
}

int retValueNtUserEnumDisplayDevices = -1;
NTSTATUS __stdcall hkNtUserEnumDisplayDevices(PUNICODE_STRING pustrDevice, DWORD iDevNum, PDISPLAY_DEVICEW pdispdev, DWORD dwFlags) {
	_asm {
		mov retValueNtUserEnumDisplayDevices, eax;
	}
	
	std::wcout << "[NtUserEnumDisplayDevices2] " << pdispdev->DeviceID << std::endl;
	wchar_t* subStr = wcsstr(pdispdev->DeviceID, L"15AD");
	do {
		int addr = ((int)subStr - (int)&pdispdev->DeviceID[0]) / 2;
		for (int j = 0; j < 4; j++) // 
			pdispdev->DeviceID[addr + j] = L'2';

		subStr = wcsstr(pdispdev->DeviceID, L"15AD");
	} while (subStr);
	std::wcout << "[NtUserEnumDisplayDevices] PATCHED => " << pdispdev->DeviceID << std::endl;

	if (retValueNtUserEnumDisplayDevices == 0) {
		return retValueNtUserEnumDisplayDevices;
	}

	return retValueNtUserEnumDisplayDevices;
}

int retValuehkWow64GetNativeSystemInformation = -1;
NTSTATUS __stdcall hkNtWow64GetNativeSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	_asm {
		mov retValuehkWow64GetNativeSystemInformation, eax;
	}

	//std::wcout << "[NtWow64GetNativeSystemInformation] Class: " << SystemInformationClass << std::endl;
	if (retValuehkWow64GetNativeSystemInformation == 0) {
		return retValuehkWow64GetNativeSystemInformation;
	}

	return retValuehkWow64GetNativeSystemInformation;
}

int retValuehkNtQueryInformationProcess = -1;
NTSTATUS __stdcall hkNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
	_asm {
		mov retValuehkNtQueryInformationProcess, eax;
	}

	//std::wcout << "[NtWow64GetNativeSystemInformation] Class: " << SystemInformationClass << std::endl;
	if (retValuehkNtQueryInformationProcess == 0) {
		Bypass::NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength, retValuehkNtQueryInformationProcess);
		return retValuehkNtQueryInformationProcess;
	}

	return retValuehkNtQueryInformationProcess;
}

// not being used, just return default
int retValueQueryDirectoryObject = -1;
NTSTATUS __stdcall hkNtQueryDirectoryObject(HANDLE  DirectoryHandle, PVOID   Buffer, ULONG   Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG  Context, PULONG  ReturnLength) {
	_asm {
		mov retValueQueryDirectoryObject, eax;
	}

	if (retValueQueryDirectoryObject == 0 && (ReturnLength && *ReturnLength > 0)) {
		/*std::wcout << "[NtQueryDirectoryObject] Bypassing len: " << Length << ", " << ReturnSingleEntry << ", " << RestartScan << "\n";
		auto pObjDirInfo = static_cast<OBJECT_DIRECTORY_INFORMATION*>(calloc(Length, 1));
		wchar_t* name = static_cast<wchar_t*>(calloc(pObjDirInfo->Name.Length + 1, sizeof(wchar_t)));
		memcpy(name, pObjDirInfo->Name.Buffer, pObjDirInfo->Name.Length * sizeof(wchar_t));
		std::wcout << name << "\n";*/
		return retValueQueryDirectoryObject;
	}

	return retValueQueryDirectoryObject;
}

std::map<std::pair<void*, void*>, const char*> LogReturnAddrOpenProcess; // create another map maybe for future
#define STATUS_ACCESS_DENIED 0xC0000022
int ntOpenProcessRetValue = -1;
NTSTATUS __stdcall hkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
	_asm {
		mov ntOpenProcessRetValue, eax;
	}

	//printf("OpenProcessHook => Ret: %d | PID: %d\n", ntOpenProcessRetValue, (DWORD)ClientId->UniqueProcess);
	// patch here
	DWORD processId = (DWORD)ClientId->UniqueProcess;
	if (ntOpenProcessRetValue == 0 && (processId == 0 || processId == 4)) { // success
		// patch return
		printf("[NtOpenProcess] Bypassed PID %d\n", processId);
		ntOpenProcessRetValue = STATUS_ACCESS_DENIED; // STATUS_ACCESS_DENIED
		return ntOpenProcessRetValue;
	}
	// patch end

	return ntOpenProcessRetValue;
}

int ntCreateFileRetValue = -1;
NTSTATUS __stdcall hkNtCreateFile(PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength) {
	_asm {
		mov ntCreateFileRetValue, eax;
	}

	if (ntCreateFileRetValue == 0xC0000034 ||
		ntCreateFileRetValue == 0xC000003A)
		return 0;

	// patch here
	if (ntCreateFileRetValue == 0) {
		Bypass::HkNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength, ntCreateFileRetValue);
		return ntCreateFileRetValue;
	}

	PVOID stackTrace[3] = { 0 };
	USHORT capturedFrames = 0;

	capturedFrames = RtlCaptureStackBackTrace(0, 3, stackTrace, NULL); // Capture the last 3 frames.
	capturedFrames = (capturedFrames) ? capturedFrames : RtlCaptureStackBackTrace(0, 3, stackTrace, NULL); // sometimes need to request stack again
	/*for (int index = 0; index < capturedFrames; index++)
		printf("Frame: %#010x\n", stackTrace[index]);*/

	if (stackTrace[1] == MapReturnAddress) {// is it LogReturnAddr allocating memory?
		return 0; // yes then just return dont add it to the map else we get a endless loop lol.
	}
	// patch end

	return ntCreateFileRetValue;
}

int ntReadFileRetValue = -1;
NTSTATUS __stdcall hkNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
	_asm {
		mov ntReadFileRetValue, eax;
	}

	// patch here
	if (ntReadFileRetValue == 0) {
		Bypass::HkNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key, ntReadFileRetValue);
		return ntReadFileRetValue;
	}
	// patch end

	return ntReadFileRetValue;
}

int ntQueryInformationFileRetValue = -1;
NTSTATUS __stdcall hkNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
	_asm {
		mov ntQueryInformationFileRetValue, eax;
	}

	// patch here
	if (ntQueryInformationFileRetValue == 0) {
		Bypass::HkNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass, ntQueryInformationFileRetValue);
		return ntQueryInformationFileRetValue;
	}
	// patch end

	return ntQueryInformationFileRetValue;
}

int ntQueryDirectoryFileExRetValue = -1;
NTSTATUS __stdcall hkNtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName) {
	_asm {
		mov ntQueryDirectoryFileExRetValue, eax;
	}

	// patch here
	if (ntQueryDirectoryFileExRetValue == 0) {
		//Bypass::HkNtQueryDirectoryFileExRetValue(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName, ntQueryDirectoryFileExRetValue);
		return ntQueryDirectoryFileExRetValue;
	}
	// patch end

	return ntQueryDirectoryFileExRetValue;
}

int ntDeviceIoControlFileRetValue = -1;
NTSTATUS __stdcall hkNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
	_asm {
		mov ntDeviceIoControlFileRetValue, eax;
	}

	// patch here
	std::cout << "[DeviceIoControlFile] Code: " << IoControlCode << std::endl;
	if (ntDeviceIoControlFileRetValue == 0) {
		Bypass::HkNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ntDeviceIoControlFileRetValue);
		return ntDeviceIoControlFileRetValue;
	}
	// patch end

	return ntDeviceIoControlFileRetValue;
}

int ntOpenFileRetValue = -1;
NTSTATUS __stdcall hkNtOpenFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions) {
	_asm {
		mov ntOpenFileRetValue, eax;
	}

	// patch here
	if (ntOpenFileRetValue == 0) {
		Bypass::HkNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions, ntOpenFileRetValue);
		return ntOpenFileRetValue;
	}
	// patch end

	return ntOpenFileRetValue;
}

LPVOID GetGateAddress() {
	static LPVOID retn = nullptr;

	if (retn) // already grabbed it? Then just return retn.
		return retn;

	__asm mov eax, dword ptr fs : [0xC0] // Grab the fastsyscall addr from TIB.
		__asm mov retn, eax // Move it into our retn value.

	return retn; // return the gate addr.
}

//uint16_t lastOrdinal = -1;
int index = 0;
void testLog(uint32_t ordinal) {
#if SYSCALL_LOG
	// hardcoded
	uint32_t arg = 0;
	uint32_t threadId = 0;

	_asm {
		pushad;
		mov eax, [esp + 0x58];
		mov arg, eax;
		mov eax, fs: [0x24] ;
		mov threadId, eax;
		popad;
	}

	int currentIndex = index++;
	auto it = HeavensGate::syscallLog.find(ordinal);
	if (it == HeavensGate::syscallLog.end()) {
		HeavensGate::syscallLog[ordinal] = 1;
		HeavensGate::syscallOrder[currentIndex] = ordinal;
		HeavensGate::syscallArg[currentIndex] = arg;
		return;
	}

	HeavensGate::syscallLog[ordinal]++;
	HeavensGate::syscallOrder[currentIndex] = ordinal;
	HeavensGate::syscallArg[currentIndex] = arg;
#endif
}

void __declspec(naked) hkWow64Transition() {
	// eax holds the ordinal.
	__asm
	{
		// logging syscall
#if SYSCALL_LOG
		cmp HeavensGate::logEnabled, 0;
		je Wow64hook;
		push eax;
		call testLog;
		pop eax;
#endif

	Wow64hook: // really wanna do switch case jmp here
		cmp eax, Ordinal::NtGetContextThread; // is the ordinal NtGetContextThread?
		je hookNtGetContextThread; // if so jump to it.
		cmp eax, Ordinal::NtQuerySystemInformation;
		je hookNtQuerySystemInformation;
		cmp eax, Ordinal::NtOpenProcess;
		je hookNtOpenProcess;
		cmp eax, Ordinal::NtCreateFile;
		je hookNtCreateFile;
		cmp eax, Ordinal::NtQuerySystemInformationEx;
		je hookNtQuerySystemInformationEx;
		cmp eax, Ordinal::NtPowerInformation;
		je hookNtPowerInformation;
		cmp eax, Ordinal::NtOpenDirectoryObject;
		je hookNtOpenDirectoryObject;
		cmp eax, Ordinal::NtQueryDirectoryObject;
		je hookNtQueryDirectoryObject;
		cmp eax, Ordinal::NtWow64GetNativeSystemInformation;
		je hookNtWow64GetNativeSystemInformation;
		cmp eax, Ordinal::NtQueryInformationProcess;
		je hookNtQueryInformationProcess;
		cmp eax, Ordinal::NtReadFile;
		je hookNtReadFile;
		cmp eax, Ordinal::NtQueryInformationFile;
		je hookNtQueryInformationFile;
		//cmp eax, Ordinal::NtUserEnumDisplayDevices;
		//je hookNtUserEnumDisplayDevices;
		/*cmp eax, Ordinal::NtQueryDirectoryFileEx;
		je hookNtQueryDirectoryFileEx;*/
		/*cmp eax, Ordinal::NtDeviceIoControlFile;
		je hookNtDeviceIoControlFile;
		cmp eax, Ordinal::NtOpenFile;
		je hookNtOpenFile;*/

		jmp CallOriginal; // jump to original.

	hookNtGetContextThread:
		mov eax, hkNtGetContextThread; // move our func into eax.
		mov[esp + 0], eax; // replace latest returnaddr with our func this will cause the original function to jump to our hook instead of its supposed destination.
		// From observing the last returnaddress always resides in esp + 0 which is pretty weird
		// even when setting up the frame the returnaddress is at a weird location
		// but this seems to works so we'll roll with that.
		// With this we can modify eax which will be the return value after the actual syscall in 64bit went through.
		// So now we can modify parameters when our hook gets called and the returnvalue which gives us the complete control as when using a normal hook.
		mov eax, Ordinal::NtGetContextThread; // give eax the ordinal again.
		jmp CallOriginal; // call original.

	hookNtQuerySystemInformation: // new copy lmao, conditions can make code clean
		mov eax, hkNtQuerySystemInformation; // REMOVED ANY COMMENT, FOR EXPLANATIONS CHECK ABOVE
		mov[esp + 0], eax;
		mov eax, Ordinal::NtQuerySystemInformation; // give eax the ordinal again.
		jmp CallOriginal; // call original.

	hookNtOpenProcess:
		mov eax, hkNtOpenProcess;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtOpenProcess;
		jmp CallOriginal;

	hookNtCreateFile:
		mov eax, hkNtCreateFile;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtCreateFile;
		jmp CallOriginal;

	hookNtDeviceIoControlFile:
		mov eax, hkNtDeviceIoControlFile;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtDeviceIoControlFile;
		jmp CallOriginal;

	hookNtOpenFile:
		mov eax, hkNtOpenFile;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtOpenFile;
		jmp CallOriginal;

	hookNtQuerySystemInformationEx:
		mov eax, hkNtQuerySystemInformationEx;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtQuerySystemInformationEx;
		jmp CallOriginal;

	hookNtPowerInformation:
		mov eax, hkNtPowerInformation;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtPowerInformation;
		jmp CallOriginal;

	hookNtOpenDirectoryObject:
		mov eax, hkNtOpenDirectoryObject;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtOpenDirectoryObject;
		jmp CallOriginal;

	hookNtQueryDirectoryObject:
		mov eax, hkNtQueryDirectoryObject;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtQueryDirectoryObject;
		jmp CallOriginal;

	hookNtWow64GetNativeSystemInformation:
		mov eax, hkNtWow64GetNativeSystemInformation;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtWow64GetNativeSystemInformation;
		jmp CallOriginal;

	hookNtQueryInformationProcess:
		mov eax, hkNtQueryInformationProcess;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtQueryInformationProcess;
		jmp CallOriginal;

	hookNtQueryDirectoryFileEx:
		mov eax, hkNtQueryDirectoryFileEx;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtQueryDirectoryFileEx;
		jmp CallOriginal;

	hookNtReadFile:
		mov eax, hkNtReadFile;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtReadFile;
		jmp CallOriginal;

	hookNtQueryInformationFile:
		mov eax, hkNtQueryInformationFile;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtQueryInformationFile;
		jmp CallOriginal;

	hookNtUserEnumDisplayDevices:
		mov eax, hkNtUserEnumDisplayDevices;
		mov[esp + 0], eax;
		mov eax, Ordinal::NtUserEnumDisplayDevices;
		jmp CallOriginal;

	CallOriginal:
		jmp NewHeavensGate; // jump to our new allocated heavensgate.
	}
}

DWORD GetOrdinal(const HMODULE NtDll, const char* NtApi) {
	for (auto entry : Bypass::syscallMap) {
		if (strstr(entry.second.c_str(), NtApi)) {
			return entry.first;
		}
	}

	return -1; // error handling.
}

bool HeavensGate::PrepHeavensGate() {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll"); // I suggest grabbing the module in a different way.
	if (!ntdll)
		return false;

	// TODO: make some array instead of define one by one
	Ordinal::NtGetContextThread = GetOrdinal(ntdll, "NtGetContextThread");
	if (Ordinal::NtGetContextThread == -1) // Well if it failed return to avoid a crash.
		return false;

	Ordinal::NtQuerySystemInformation = GetOrdinal(ntdll, "NtQuerySystemInformation");
	if (Ordinal::NtQuerySystemInformation == -1)
		return false;

	Ordinal::NtOpenProcess = GetOrdinal(ntdll, "NtOpenProcess");
	if (Ordinal::NtOpenProcess == -1)
		return false;

	Ordinal::NtCreateFile = GetOrdinal(ntdll, "NtCreateFile");
	if (Ordinal::NtCreateFile == -1)
		return false;

	Ordinal::NtDeviceIoControlFile = GetOrdinal(ntdll, "NtDeviceIoControlFile");
	if (Ordinal::NtDeviceIoControlFile == -1)
		return false;

	Ordinal::NtOpenFile = GetOrdinal(ntdll, "NtOpenFile");
	if (Ordinal::NtOpenFile == -1)
		return false;

	Ordinal::NtReadFile = GetOrdinal(ntdll, "NtReadFile");
	if (Ordinal::NtReadFile == -1)
		return false;

	Ordinal::NtQuerySystemInformationEx = GetOrdinal(ntdll, "NtQuerySystemInformationEx");
	if (Ordinal::NtQuerySystemInformationEx == -1)
		return false;

	Ordinal::NtPowerInformation = GetOrdinal(ntdll, "NtPowerInformation");
	if (Ordinal::NtPowerInformation == -1)
		return false;

	Ordinal::NtOpenDirectoryObject = GetOrdinal(ntdll, "NtOpenDirectoryObject");
	if (Ordinal::NtOpenDirectoryObject == -1)
		return false;

	Ordinal::NtQueryDirectoryObject = GetOrdinal(ntdll, "NtQueryDirectoryObject");
	if (Ordinal::NtQueryDirectoryObject == -1)
		return false;

	Ordinal::NtWow64GetNativeSystemInformation = GetOrdinal(ntdll, "NtWow64GetNativeSystemInformation");
	if (Ordinal::NtWow64GetNativeSystemInformation == -1)
		return false;

	Ordinal::NtQueryInformationProcess = GetOrdinal(ntdll, "NtQueryInformationProcess");
	if (Ordinal::NtQueryInformationProcess == -1)
		return false;

	Ordinal::NtQueryInformationFile = GetOrdinal(ntdll, "NtQueryInformationFile");
	if (Ordinal::NtQueryInformationFile == -1)
		return false;

	const char* pattern = "\xFF\x86\x00\x00\x00\x00\x85";
	const char* mask = "xx????x";
	const WCHAR* ntdllModuleName = L"ntdll.dll";
	MapReturnAddress = PatternScan::ExternalModuleScan(GetCurrentProcess(), GetCurrentProcessId(), (wchar_t*)ntdllModuleName, (char*)pattern, (char*)mask);
	if (!MapReturnAddress)
		return false;

	return true;
}

bool HeavensGate::PatchHeavensGate(LPVOID GateAddress, void* Buffer, const std::size_t Size) {
	DWORD OldProtect = 0;
	if (!VirtualProtectEx(GetCurrentProcess(), GateAddress, 0x10, PAGE_EXECUTE_READWRITE, &OldProtect)) // change the protection of the gate so we can write to it.
		return false;

	if (!memcpy(GateAddress, Buffer, Size)) // patch the gate.
		return false;

	if (!VirtualProtectEx(GetCurrentProcess(), GateAddress, 0x10, OldProtect, &OldProtect)) // restore protection of the gate.
		return false;

	return true;
}

bool HeavensGate::HookHeavensGate() {
#if SYSCALL_LOG
	memset(&syscallOrder[0], 0, 5000000);
#endif
	if (!GetGateAddress())
		return false;

	void* HookGate = &hkWow64Transition; // Grab our hooks addr.

	if (!HookGate)
		return false;

	// Push Detour.
	// Basically a jmp but we push a new returnaddr onto the stack and pop it with ret to get to that location.
	std::uint8_t TrampolineBytes[] =
	{
		0x68, 0x00, 0x00, 0x00, 0x00,       // push 0xADDRESS
		0xC3,                               // ret
		0x90, 0x90, 0x90                    // nop, nop, nop
	};

	if (!memcpy(&TrampolineBytes[1], &HookGate, 4)) // copy our naked function address into the trampoline.
		return false;

	NewHeavensGate = VirtualAlloc(nullptr, 0x10, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); // Allocate new memory for the heavens gate copy.
	if (!NewHeavensGate)
		return false;

	if (!memcpy(NewHeavensGate, GetGateAddress(), 9)) // copy the gate into our allocated memory.
		return false;

	if (!HeavensGate::PatchHeavensGate(GetGateAddress(), TrampolineBytes, sizeof(TrampolineBytes))) // patch the gate.
		return false;

	return true;
}

void HeavensGate::DumpSyscallLogs() {
#if SYSCALL_LOG
	std::ofstream myfile;
	myfile.open("syscall.txt");

	myfile << "Total syscall: " << HeavensGate::syscallLog.size() << "\n";
	for (auto it : HeavensGate::syscallLog) {
		auto syscallIt = Bypass::syscallMap.find(it.first);
		std::string methodName("");
		if (syscallIt != Bypass::syscallMap.end())
			methodName = syscallIt->second;

		myfile << "[" << methodName.c_str() << "]: 0x" << std::hex << it.first << " " << it.second << "\n";
		//printf("[%s]: %#010x %d\n", methodName.c_str(), it.first, it.second);
	}
	//printf("Syscall log dump done.\n");
	int lastIndex = 0;
	for (int index = 0; index < 5000000; index++) {
		if (HeavensGate::syscallOrder[index] == 0)
			break;

		lastIndex = index;
	}

	printf("lastindez%d\n", lastIndex);

	myfile << "Enumerating calls by order z to a\n";
	for (int index = lastIndex; index >= 0; index--) {
		uint32_t ordinalId = HeavensGate::syscallOrder[index];
		auto syscallIt = Bypass::syscallMap.find(ordinalId);
		std::string methodName("");
		if (syscallIt != Bypass::syscallMap.end())
			methodName = syscallIt->second;

		myfile << "[" << methodName.c_str() << "]: 0x" << std::hex << ordinalId << " Arg: " << HeavensGate::syscallArg[index] << "\n";
	}
	myfile.close();
#endif
}