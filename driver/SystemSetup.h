#pragma once
#include "Incloods.h"

namespace sysSetup
{
	NTSTATUS CreateConfig(PCHAR procName, bool isKernelmode, bool isUsermode);
	NTSTATUS initialize();
	NTSTATUS fetchFileBytes(PCWSTR filePath, PVOID* buffer, PSIZE_T bufferSize);
	namespace setup
	{
		
		NTSTATUS setup();
	}
}

namespace sysData
{
	struct sEPROCESS
	{

	};
}

namespace sysConfig
{
	extern bool cheatIsInternal;
	extern bool acIsKernel;
	extern bool acIsUsermode;
	extern char* targetName;
	extern char* targetNameTrimmed;
	extern ULONG processID;
}