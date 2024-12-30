#pragma once
#include "includes.h"

namespace Helper
{
	extern long windowsVersion;

	NTSTATUS GetWindowsVersion();
	NTSTATUS HideSelf();
	NTSTATUS ResolveSyscalls();
	UINT64 PollUntilProcess();
	bool shutdownDriver();
	void SleepInMilliseconds(LONG ms);
	uintptr_t find_eprocess(char* process_name);
	_HANDLE_TABLE_ENTRY* ExpLookupHandleTableEntry(ULONG64* pHandleTable, ULONG64 Handle);

	namespace internalData
	{
		extern HANDLE threadHandle;
	}
	namespace Config
	{
		extern bool cheatIsInternal;
		extern bool acIsKernel;
		extern bool acIsUsermode;
		extern char* targetName;
		extern char* targetNameTrimmed;
		extern ULONG processID;

		NTSTATUS CreateConfig(char* ProcessName, bool IsKernelAC, bool IsInternalCheat);
	}
}

