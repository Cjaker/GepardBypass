Tested on Win10x64 20H2 and not latest gepard

Last test some months ago

Features:
- Breakpoints (HWBP & INT3 trap flag)
- Integrity of modified files on game directory
- Scan of loaded drivers
- Hide processes

You can use it by two ways:
1) Injecting it (don't try random injection method, be smart and try before/after game loads i don't remember)
2) Patching some dll from folder and make it load your dll (patch hash for that and you will be safe)

No tutorial released, developed this dll for studies purposes about Windows API (kernel, ntdll)

Suggest using IDA on windows libraries for updating and studying

Good stuff is a method to avoid using usual methods for vectored exceptions (check on bypass.cpp, handled exceptions by dll)

If i miss something feel free to fix me, released because i don't have any use on this

Recommended change your detours library to avoid use default VirtualProtect methods, they are detected & hooked (try use ntdll one)

Got some resources and studied from:
- Unknowncheats
- Guidedhacking
- https://github.com/Rat431/ColdHide_V2
- ScyllaHide
