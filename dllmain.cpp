#include "pch.h"
#include "bypass.h"
#include "utils.h"
#include "threading.h"
#include "addresses.h"
#include "winapi.h"
#include "exceptionhandler.h"
#include "breakpoint.h"

// used for autoloading
#define DllExport   __declspec( dllexport )
DllExport void init() {

}

/*
[AC-Features]
- integrity validation of code section (bypass with 0xCC or analyze they crc methods and patch all them, mainly if they have some shellcode array)
- integrity validation of EXE file (not tried yet, but very probably they will user read file methods)
- integrity validation of DLLs in the game client folder (to bypass .asi loading hook FindFirstFileW or next and avoid returning valid handle of new file)
- encryption of network packets with dynamic key
- protection against dll injection (thread hijack will be fine)
- protection against WPE/RPE/OpenKore
- possibility to get unique ID of player(it isn't based on MAC) (never tried, but maybe using spoof techniques should be fine)
- possibility to block player by unique ID
- possibility to set limit of active game windows (some techniques too, probably mutex etc)
- prevents starting on virtual machines(optional)
- blocks using popular cheat tools(PotND, meth4u, xRag, xLike, RoTools and other) (process enumeration lol patched)

- prevents emulation of mouse and keyboard. It blocks macro/autopotion tools. (bypass driver interception and probably rawInputData)
- prevents using nodelay. It blocks a lot methods to get this effect. (probably they check for spammed packet)
*/

void PatchHooks() {
	Threading::Sleep(5000);
	Bypass::HideDRx();
	Bypass::PatchHooks();
	HWBreakpoint::Set((void*)g_addresses.receivePacketMidHookAddr, 1, HWBreakpoint::Condition::ReadWrite); // patch crc
	Breakpoint::SetInt3(g_addresses.receivePacketMidHookAddr); // receive packets
}

void StartBypass() {
	g_addresses.Initialize(WinApi::GetModuleBaseAddress(GetCurrentProcessId(), L"Jogar.exe")); // Jogar.exe = game executable name

	Bypass::Initialize();
	Bypass::PatchFreeConsole();

	if (!Utils::InitializeConsole()) { // No console wtf
		return;
	}

	// auto load this dll by adding as dependency of binkw32
	Bypass::EraseHeaders(GetModuleHandleA("binkw32.dll"));
	Bypass::EraseHeaders(GetModuleHandleA("usern32.dll"));
	Bypass::UnlinkModule(L"binkw32.dll");
	Bypass::UnlinkModule(L"usern32.dll");
	Bypass::Wow64Hook();
	Threading::CreateFakeThread(PatchHooks);

	//Bypass::SetExceptionFilter(NULL); // Not necessary as they handler will not be trigered with our hooks
	//Bypass::WaitAndLogSyscall(); // Good for logging syscall, but not perfect

	// Hook for receiving packets
	//HWBreakpoint::Set((void*)recvPacketOffset, 1, HWBreakpoint::Condition::Execute);

	/* NOTES 
	  - To bypass CRC checks on ntdll methods just put HWBP read on start/end of function, on start trigger just remove hook (not the best solution and can crash)
	*/

	/* Some error codes
	   Gepard::SY => happens when something goes wrong or hook return badly (tested on NtCreateFile syscall hook)
	   Gepard::SE => Memory integrity
	   ::10 = Fake address on CRC or different of section
	   ::40 = Modified .code section
	   Gepard::XX => Function Hooked or edited
	*/

	/* Study Notes 
	   - On exception stuff when code triggers some exception he will call nt functions by this order: 
	   KiUser -> call RtlDispatchException (this one will check if has some handler to handle exception) if succeed call ZwContinue, otherwise RaiseException
	*/
}

void Initialize() {
	StartBypass();
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		Initialize();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

