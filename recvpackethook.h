#pragma once
#ifndef RECVPACKET_HOOK_H
#define RECVPACKET_HOOK_H
#include "addresses.h"

class RecvPacketHook {
public:
	static void ReceivePacketMidHook();
	static void OnReceivePacket();
};

#endif