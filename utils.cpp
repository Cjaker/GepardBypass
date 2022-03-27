#include "pch.h"
#include "utils.h"

bool Utils::InitializeConsole() {
	BOOL result = AllocConsole();
	if (!result)
		return result;

	// I don't think this next instructions will fail, maybe in case of AC using some methods/hooks.
	FILE* fDummy;
	freopen_s(&fDummy, "CONIN$", "r", stdin);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
	return true;
}
