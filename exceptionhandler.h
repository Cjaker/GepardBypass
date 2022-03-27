#pragma once
#ifndef EXCEPTION_HANDLER_H
#define EXCEPTION_HANDLER_H
#include "addresses.h"
#include "recvpackethook.h"
#include "hwbreakpoint.h"
#include "detours.h"
#include "threading.h"
#include "breakpoint.h"
#include <cstdint>

class ExceptionHandler {
public:
	static void MainExceptionHandler(_EXCEPTION_RECORD* ep, CONTEXT* context);
	static void SingleStepHandler(uint32_t breakpointAddr, _EXCEPTION_RECORD* ep, CONTEXT* context);
	static void BreakpointHandler(uint32_t breakpointAddr, _EXCEPTION_RECORD* ep, CONTEXT* context);
	static void Resume(CONTEXT* context);
	static void DisableBreakpoint(CONTEXT* context, int index);
};

#endif