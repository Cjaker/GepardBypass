#ifndef HOOK
#define HOOK

#include <windows.h>
#include <cstdint>

void HookJMP(DWORD dwAddress, DWORD dwFunction);
void HookCall(DWORD dwAddress, DWORD dwFunction);
void HookCallN(DWORD dwAddress, DWORD dwFunction);
void Nop(DWORD dwAddress, int size);
void OverWriteByte(DWORD addressToOverWrite, BYTE newValue);
void OverWriteWord(DWORD addressToOverWrite, WORD newValue);
void OverWrite(DWORD addressToOverWrite, DWORD newValue);
void OverWriteBytes(DWORD addressToOverWrite, uint8_t* bytes, int bytesCount);

#endif