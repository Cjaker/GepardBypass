#include "pch.h"
#include "recvpackethook.h"

uint32_t recvBufferAddr = 0;
int recvBufferLen = 0;
int isLoginPacket = 0;

void RecvPacketHook::OnReceivePacket() {
	size_t length = recvBufferLen;
	printf("[RecvPacketHook][IsLogin: %s] Len %d\n", (isLoginPacket ? "true" : "false"), length);
	//LogGetByte();
}

_declspec(naked) void RecvPacketHook::ReceivePacketMidHook() {
	_asm {
		// as we change our hook to int3 at pop esi instruction, get from esp + 0
		mov esi, [ESP + 0];
		mov recvBufferAddr, esi;
		cmp eax, 0;
		je isLoginPacketRecv;
		xor esi, esi;
		mov si, [eax];
		mov recvBufferLen, esi;
		mov isLoginPacket, 0;
		jmp endFlow;

	isLoginPacketRecv:
		mov isLoginPacket, 1;
		xor esi, esi;
		mov si, [esp + 0xC];
		mov recvBufferLen, esi;
		jmp endFlow;

	endFlow:
		mov esi, recvBufferAddr;
		pushad;
		call RecvPacketHook::OnReceivePacket;
		popad;
		pop esi;
		jmp g_addresses.receivePacketMidHookJmpBackAddr;
	}
}
