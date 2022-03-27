#include "pch.h"
#include "addresses.h"

Addresses g_addresses;
void Addresses::Initialize(uint32_t baseAddr) {
	this->baseAddr = baseAddr;

	receivePacketSubAddr += baseAddr;
	receivePacketMidHookAddr = receivePacketSubAddr + 0x16F;
	receivePacketMidHookJmpBackAddr = receivePacketMidHookAddr + 1; // int3 breakpoint, jmp to next instruction
}
