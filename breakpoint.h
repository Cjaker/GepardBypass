#pragma once
#ifndef BREAKPOINT_H
#define BREAKPOINT_H
#include "ntdll.h"
#include <Windows.h>

class Breakpoint {
public:
	static void SetInt3(DWORD address);
	static void ClearInt3(DWORD address);
	static int GetOriginalInstruction(DWORD address);
};

#endif