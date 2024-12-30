#pragma once
#include "includes.h"

#pragma warning (disable : 4996)
#pragma warning (disable : 4100)
#pragma warning (disable : 4101)
#pragma warning (disable : 4189)

namespace sys
{
	NTSTATUS StealthAlloc(PEPROCESS target, PVOID* MappedAddress, SIZE_T allocationSize);
	NTSTATUS N_StealthSetupAndMapDll(PEPROCESS target, PVOID* MappedAddress, PVOID Dll, SIZE_T allocationSize);
	NTSTATUS MapDll(PEPROCESS target, PVOID MappedAddress, PVOID Dll, SIZE_T DllSize);
	NTSTATUS TriggerDllStart();
	NTSTATUS ResolveImports(PVOID DllBase, PEPROCESS TargetProcess);
	NTSTATUS setupDll(PEPROCESS target, PVOID dllBuffer, SIZE_T dllSizeRaw, PVOID* returnValue, PVOID ntoskrnl);
}