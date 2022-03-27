#pragma once
#ifndef WINAPI_H
#define WINAPI_H

class WinApi {
public:
	static uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName);
};

#endif