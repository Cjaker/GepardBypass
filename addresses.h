#pragma once
#ifndef ADDRESSES_H
#define ADDRESSES_H
#include <cstdint>

class Addresses {
public:
	void Initialize(uint32_t baseAddr);

	uint32_t receivePacketSubAddr = 0x4C5860;
	uint32_t receivePacketMidHookAddr = 0x0;
	uint32_t receivePacketMidHookJmpBackAddr = 0x0;

	uint32_t baseAddr;
};

extern Addresses g_addresses;
#endif