#include "pch.h"
#include "exceptionhandler.h"

unsigned char ntdllQueryInformationThreadBytes[] = { 0xB8, 0x25, 0x00, 0x00, 0x00 };
DWORD ntQueryInformationThreadAddr = (DWORD)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
void ExceptionHandler::MainExceptionHandler(_EXCEPTION_RECORD* ep, CONTEXT* context) {
	// if is int3 breakpoint so we have the breakpoint address in exception pointer
	if (ep->ExceptionCode == EXCEPTION_BREAKPOINT) {
		printf("[MainExceptionHandler] Breakpoint INT3 triggered: %#010x\n", (uint32_t)ep->ExceptionAddress);
		ExceptionHandler::BreakpointHandler((uint32_t)ep->ExceptionAddress, ep, context);
		return;
	}

	// first get what breakpoint was triggered
	uint32_t breakpointAddr = Threading::GetCurrentBreakpointAddress(context);

	//printf("%#010x %#010x %#010x %#010x %#010x %#010x %#010x %#010x\n", context->Dr0, context->Dr1, context->Dr2, context->Dr3, context->Dr7, context->EFlags, context->ContextFlags, ep->ExceptionFlags);
	//printf("CODE: %#010x\n", ep->ExceptionCode);
	//printf("ADDR: %#010x\n", (uint32_t)ep->ExceptionAddress);
	//printf("EIP: %#010x\n", (uint32_t)context->Eip);
	if (!breakpointAddr) // no breakpoint addr so isn't our problem
		return;

	printf("[MainExceptionHandler] Breakpoint triggered: %#010x\n", breakpointAddr);
	if (ep->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		ExceptionHandler::SingleStepHandler(breakpointAddr, ep, context);
	}
}

void ExceptionHandler::SingleStepHandler(uint32_t breakpointAddr, _EXCEPTION_RECORD* ep, CONTEXT* context) {
	if (breakpointAddr == g_addresses.receivePacketMidHookAddr) { // execution type
		uint8_t originalInstruction = Breakpoint::GetOriginalInstruction(breakpointAddr);
		if (originalInstruction == -1) { // not hooked?
			context->Dr6 = 0;
			return;
		}

		DWORD startRegister = (DWORD)&context->Edi;
		for (int index = 0; index < 6; index++) {
			DWORD* currentRegister = ((DWORD*)(startRegister + (index * sizeof(DWORD))));
			if ((uint8_t)*currentRegister == 0xCC) {
				*currentRegister -= 0xCC; // i know have better ways, but my head is lazy now...
				*currentRegister += (uint8_t)originalInstruction; // get original and sum
			}
		}

		context->Dr6 = 0;
	} else if (breakpointAddr == ntQueryInformationThreadAddr) { // not being used for now
		printf("[ExceptionHandler::SingleStepHandler] Handling CRC check for ntQueryInformationThread\n");
		// patch the first byte too... he got one, don't let him go.
		// iterate all registers and patch the read byte
		DWORD startRegister = (DWORD)&context->Edi;
		for (int index = 0; index < 6; index++) {
			DWORD* currentRegister = ((DWORD*)(startRegister + (index * sizeof(DWORD))));
			if ((uint8_t)*currentRegister == 0xE9) {
				*currentRegister -= 0xE9; // i know have better ways, but my head is lazy now...
				*currentRegister += (uint8_t)ntdllQueryInformationThreadBytes[0]; // get original and sum
			}
		}

		// restore original bytes of hook and put breakpoint on last intruction byte
		// clear dr0 to avoid breakpoint on access when restoring bytes
		HWBreakpoint::Clear((void*)(ntQueryInformationThreadAddr));
		context->Dr0 = 0;

		// restore bytes by detaching (if is hooked)
		/*DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)ntQueryInformationThreadOrig, __NtQueryInformationThread);
		DetourTransactionCommit();*/
		context->Dr6 = 0;
	} else if (breakpointAddr == (ntQueryInformationThreadAddr + 0xE)) {
		// set breakpoint at function start and hook again
		/*DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)ntQueryInformationThreadOrig, __NtQueryInformationThread);
		DetourTransactionCommit();*/
		HWBreakpoint::Set((void*)(ntQueryInformationThreadAddr), 1, HWBreakpoint::Condition::ReadWrite);
		context->Dr0 = ntQueryInformationThreadAddr;
		context->Dr6 = 0;
	}
}

void ExceptionHandler::BreakpointHandler(uint32_t breakpointAddr, _EXCEPTION_RECORD* ep, CONTEXT* context) {
	if (breakpointAddr == g_addresses.receivePacketMidHookAddr) {
		// redirect EIP to our hook
		context->Eip = (DWORD)&RecvPacketHook::ReceivePacketMidHook;
	}

	// resume int3 breakpoint execution
	ExceptionHandler::Resume(context);
}

// important to use if is hwbp execute
void ExceptionHandler::Resume(CONTEXT* context) {
	context->EFlags = 0x00010000; // resume flag value
	context->Dr6 = 0; // clear dr6 for next exception
}

void ExceptionHandler::DisableBreakpoint(CONTEXT* context, int index) {
	context->Dr7 &= ~(1ULL << (2 * index));
}