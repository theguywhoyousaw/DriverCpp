#pragma warning (disable : 4189)
#pragma warning (disable : 4996)
#pragma warning (disable : 4100)

#pragma once
#include "includes.h"
#include "Helper.h"  //Rename this
#include "Mem.h"     //Mem
#include "sys_ops.h" //System

extern "C" int _fltused = 1; //For speed modification

bool hookinf();
LONG callback(CONTEXT* ContextRecord, EXCEPTION_RECORD* ExceptionRecord) 
{
    (void)ContextRecord;
    (void)ExceptionRecord;
    return 1;
}
//0x430 bytes (sizeof)

double speedMultiplier = 3;

typedef NTSTATUS(*NtCreateFile_t)(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength);

typedef NTSTATUS(*NtReadVirtualMemory_t)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
);

//Speedhacking
typedef NTSTATUS(*NtQueryPerformanceCounter_t)(
    _Out_     PLARGE_INTEGER PerformanceCounter,
    _Out_opt_ PLARGE_INTEGER PerformanceFrequency
    );
typedef NTSTATUS(*NtQuerySystemTime_t)(
    _Out_ PLARGE_INTEGER SystemTime
    );
typedef NTSTATUS(*NtSetTimerResolution_t)(
    _In_ ULONG DesiredResolution,
    _In_ BOOLEAN SetResolution,
    _Out_ PULONG CurrentResolution
    );
typedef NTSTATUS(*NtQueryTimerResolution_t)(
    _Out_ PULONG MinimumResolution,
    _Out_ PULONG MaximumResolution,
    _Out_ PULONG CurrentResolution
    );
typedef NTSTATUS(*ZwWaitForSingleObject_t)(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );
typedef NTSTATUS(*ZwDelayExecution_t)(
    _In_ BOOLEAN Alertable,
    _In_ PLARGE_INTEGER DelayInterval
    );


static NtQueryPerformanceCounter_t OriginalNtQueryPerformanceCounter = NULL;
static NtQuerySystemTime_t OriginalNtQuerySystemTime = NULL;
static NtSetTimerResolution_t OriginalNtSetTimerResolution = NULL;
static NtQueryTimerResolution_t OriginalNtQueryTimerResolution = NULL;
static ZwWaitForSingleObject_t OriginalZwWaitForSingleObject = NULL;
static ZwDelayExecution_t OriginalZwDelayExecution = NULL;


static wchar_t IfhMagicFileName[] = L"ifh--";
static UNICODE_STRING StringNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
static NtCreateFile_t OriginalNtCreateFile = NULL;
static UNICODE_STRING StringNtReadVirtualMemory = RTL_CONSTANT_STRING(L"NtReadVirtualMemory");
static UNICODE_STRING StringZwReadVirtualMemory = RTL_CONSTANT_STRING(L"ZwReadVirtualMemory");
static NtReadVirtualMemory_t OriginalNtReadVirtualMemory = NULL;
bool ft = true;

NTSTATUS  DetourNtQueryPerformanceCounter(
    _Out_     PLARGE_INTEGER PerformanceCounter,
    _Out_opt_ PLARGE_INTEGER PerformanceFrequency
)
{
    // Call the original function to get the real performance counter and frequency
    NTSTATUS status = OriginalNtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);

    // Speed multiplier - this controls how fast or slow time passes
    // A multiplier > 1.0 speeds up time, and a multiplier < 1.0 slows it down
    if (NT_SUCCESS(status))
    {
        // Modify the performance counter by applying the speed multiplier
        PerformanceCounter->QuadPart = (LONGLONG)(PerformanceCounter->QuadPart / speedMultiplier);

        // Optionally, adjust the performance frequency for consistency
        if (PerformanceFrequency != NULL) {
            PerformanceFrequency->QuadPart = (LONGLONG)(PerformanceFrequency->QuadPart * speedMultiplier);
        }
    }

    // Return the original status
    return status;
}
NTSTATUS DetourNtQuerySystemTime(
    _Out_ PLARGE_INTEGER SystemTime
)
{
    // Call the original function
    NTSTATUS status = OriginalNtQuerySystemTime(SystemTime);

    // Apply speed multiplier to system time
    if (NT_SUCCESS(status)) {
        SystemTime->QuadPart = (LONGLONG)(SystemTime->QuadPart / speedMultiplier);
    }

    return status;
}
NTSTATUS DetourNtSetTimerResolution(
    _In_ ULONG DesiredResolution,
    _In_ BOOLEAN SetResolution,
    _Out_ PULONG CurrentResolution
)
{
    // Modify the desired resolution by applying the speed multiplier
    /*ULONG modifiedResolution = (ULONG)(DesiredResolution / speedMultiplier);

    // Call the original function with the modified resolution
    NTSTATUS status = OriginalNtSetTimerResolution(modifiedResolution, SetResolution, CurrentResolution);

    // Optionally, modify the current resolution for consistency
    if (NT_SUCCESS(status) && CurrentResolution != NULL) {
        *CurrentResolution = (ULONG)(*CurrentResolution / speedMultiplier);
    }

    return status;*/

    return OriginalNtSetTimerResolution(DesiredResolution, SetResolution, CurrentResolution);
}
NTSTATUS DetourNtQueryTimerResolution(
    _Out_ PULONG MinimumResolution,
    _Out_ PULONG MaximumResolution,
    _Out_ PULONG CurrentResolution
)
{
    // Call the original function
    /*NTSTATUS status = OriginalNtQueryTimerResolution(MinimumResolution, MaximumResolution, CurrentResolution);

    // Apply speed multiplier to the resolution values
    if (NT_SUCCESS(status)) {
        if (MinimumResolution != NULL) {
            *MinimumResolution = (ULONG)(*MinimumResolution / speedMultiplier);
        }
        if (MaximumResolution != NULL) {
            *MaximumResolution = (ULONG)(*MaximumResolution / speedMultiplier);
        }
        if (CurrentResolution != NULL) {
            *CurrentResolution = (ULONG)(*CurrentResolution / speedMultiplier);
        }
    }

    return status;*/

    return OriginalNtQueryTimerResolution(MinimumResolution, MaximumResolution, CurrentResolution);
}
NTSTATUS DetourZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
)
{
    LARGE_INTEGER modifiedTimeout = { 0 };

    // If a timeout is provided, adjust it using the speedMultiplier
    if (Timeout != NULL) {
        modifiedTimeout.QuadPart = (LONGLONG)(Timeout->QuadPart * speedMultiplier);
    }

    // Call the original function with the modified timeout
    return OriginalZwWaitForSingleObject(Handle, Alertable, (Timeout != NULL) ? &modifiedTimeout : NULL);
}
NTSTATUS DetourZwDelayExecution(
    _In_ BOOLEAN Alertable,
    _In_ PLARGE_INTEGER DelayInterval
)
{
    LARGE_INTEGER modifiedDelay = { 0 };

    // Adjust the delay interval using the speedMultiplier
    if (DelayInterval != NULL) {
        modifiedDelay.QuadPart = (LONGLONG)(DelayInterval->QuadPart * speedMultiplier);
    }

    // Call the original function with the modified delay interval
    return OriginalZwDelayExecution(Alertable, (DelayInterval != NULL) ? &modifiedDelay : NULL);
}


NTSTATUS DetourNtReadVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
)
{
    kprintf("[+ft] Hello!");
    return OriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}

NTSTATUS DetourNtCreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength)
{
    //
    //kprintf("[+Create] infinityhook: SYSCALL");
    // We're going to filter for our "magic" file name.
    //
    if (ObjectAttributes &&
        ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer)
    {
        //
        // Unicode strings aren't guaranteed to be NULL terminated so
        // we allocate a copy that is.
        //
        PWCHAR ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
        if (ObjectName)
        {
            memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
            memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
            if (ft)
            {
                ft = false;
                kprintf("[+ft] infinityhook: TRIP");
            }
            //
            // Does it contain our special file name?
            //
            if (wcsstr(ObjectName, IfhMagicFileName))
            {
                kprintf("[+] infinityhook: Denying access to file: %wZ.\n", ObjectAttributes->ObjectName);

                ExFreePool(ObjectName);

                //
                // The demo denies access to said file.
                //
                return STATUS_ACCESS_DENIED;
            }

            ExFreePool(ObjectName);
        }
    }

    //
    // We're uninterested, call the original.
    //
    return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}
bool firsttime = true;

bool shouldHook(ULONG processId)
{
    if (processId == Helper::Config::processID)
        return true;
    return false;
}

void __fastcall SyscallStub(
    _In_ unsigned int SystemCallIndex,
    _Inout_ void** SystemCallFunction)
{
    // 
    // Enabling this message gives you VERY verbose logging... and slows
    // down the system. Use it only for debugging.
    //
    if (firsttime)
    {
        //kprintf("[FT+] infinityhook: SYSCALL %lu: 0x%p [stack: 0x%p].\n", SystemCallIndex, *SystemCallFunction, SystemCallFunction);
        firsttime = false;
    }
    


    //
    // In our demo, we care only about nt!NtCreateFile calls.
    //
    /*if (*SystemCallFunction == OriginalNtCreateFile)
    {
        *SystemCallFunction = DetourNtCreateFile;
    }

    if (SystemCallIndex == 0x003f)
    {
        OriginalNtReadVirtualMemory = (NtReadVirtualMemory_t)*SystemCallFunction;
        *SystemCallFunction = DetourNtReadVirtualMemory;
    }*/
    if (*SystemCallFunction != NULL)
    {
        if (*SystemCallFunction == OriginalNtQueryPerformanceCounter)
        {
            ULONG processId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            if (shouldHook(processId))
                *SystemCallFunction = DetourNtQueryPerformanceCounter;

        }
        if (*SystemCallFunction == OriginalNtQuerySystemTime)
        {
            ULONG processId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            if (shouldHook(processId))
                *SystemCallFunction = DetourNtQuerySystemTime;
        }

        if (*SystemCallFunction == OriginalNtSetTimerResolution)
        {
            ULONG processId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            if (shouldHook(processId))
                *SystemCallFunction = DetourNtSetTimerResolution;
        }

        if (*SystemCallFunction == OriginalNtQueryTimerResolution)
        {
            ULONG processId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            if (shouldHook(processId))
                *SystemCallFunction = DetourNtQueryTimerResolution;
        }

        if (*SystemCallFunction == OriginalZwWaitForSingleObject)
        {
            ULONG processId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            if (shouldHook(processId))
                *SystemCallFunction = DetourZwWaitForSingleObject;
        }

        if (*SystemCallFunction == OriginalZwDelayExecution)
        {
            ULONG processId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            if (shouldHook(processId))
                *SystemCallFunction = DetourZwDelayExecution;
        }
    }
}

bool initializeHooks()
{
    OriginalNtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&StringNtCreateFile);
    OriginalNtReadVirtualMemory = (NtReadVirtualMemory_t)MmGetSystemRoutineAddress(&StringNtReadVirtualMemory);
    if (!OriginalNtCreateFile)
    {
        kprintf("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtCreateFile);
        return 0;
    }

    bool stat = IfhInitialize2(SyscallStub);
    if (stat == false)
    {
        kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", stat);
        return 0;
    }
    return 1;
}

uint8_t blapttr[] =
{
    "4C 8D 15 ?? ?? ?? ?? 4C 8D 1D ?? ?? ?? ?? F7 43 78 80 00 00 00"
};

uint8_t kiSystemServiceRepeatPattern[] = {
    0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,  // lea r10, [nt!KeServiceDescriptorTable]
    0x4C, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00,  // lea r11, [nt!KeServiceDescriptorTableShadow]
    0xF7, 0x43, 0x78, 0x80, 0x00, 0x00, 0x00,  // test dword ptr [rbx+78h], 80h
    
};
BOOLEAN CompareMemory(UINT64* data, uint8_t* pattern, size_t patternSize) {
    for (size_t i = 0; i < patternSize; i++) {
        // Wildcard 0x00 means ignore this byte in the pattern
        if (pattern[i] != 0x00 && data[i] != pattern[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    PVOID  Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG NumberOfModules;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

// Declaration for NtQuerySystemInformation function pointer
typedef NTSTATUS(*NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );




PVOID GetKernelModuleBase(const char* moduleName) {
    // Function pointer for NtQuerySystemInformation
    UNICODE_STRING ntQuerySysInfoString;
    RtlInitUnicodeString(&ntQuerySysInfoString, L"NtQuerySystemInformation");
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)MmGetSystemRoutineAddress(&ntQuerySysInfoString);

    if (NtQuerySystemInformation == NULL) {
        DbgPrint("Failed to get NtQuerySystemInformation function.\n");
        return NULL;
    }

    ULONG len = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        DbgPrint("Failed to get the required length for module information.\n");
        return NULL;
    }

    // Allocate memory for the module information
    PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, len, 'modl');

    if (!pModuleInfo) {
        DbgPrint("Failed to allocate memory for module information.\n");
        ExFreePoolWithTag(pModuleInfo, 'modl');
        return NULL;
    }

    // Retrieve the module information
    status = NtQuerySystemInformation(SystemModuleInformation, pModuleInfo, len, &len);

    if (!NT_SUCCESS(status)) {
        DbgPrint("NtQuerySystemInformation failed.\n");
        ExFreePoolWithTag(pModuleInfo, 'modl');
        return NULL;
    }

    // Iterate through the list of modules to find the target module (e.g., ntoskrnl.exe)
    for (ULONG i = 0; i < pModuleInfo->NumberOfModules; i++) {
        PSYSTEM_MODULE_INFORMATION_ENTRY module = &pModuleInfo->Modules[i];
        const char* moduleBaseName = (const char*)module->FullPathName + module->OffsetToFileName;

        if (_stricmp(moduleBaseName, moduleName) == 0) {
            // Found the module, return its base address
            PVOID moduleBase = module->ImageBase;
            ExFreePoolWithTag(pModuleInfo, 'modl');
            return moduleBase;
        }
    }

    // Clean up and return NULL if module not found
    ExFreePoolWithTag(pModuleInfo, 'modl');
    return NULL;
}

uintptr_t ReadMsrLstar() 
{
    return __readmsr(IA32_LSTAR);
}

uintptr_t GetRipRelativeAddress(uint8_t* instruction, int offset) 
{
    int32_t ripOffset = *(int32_t*)(instruction + offset);
    uintptr_t instructionAddress = (uintptr_t)(instruction + 4); // RIP-relative starts 4 bytes after instruction
    return instructionAddress + ripOffset;
}

/*uintptr_t FindKiSystemServiceRepeat(uintptr_t startAddress) {
    size_t searchRange = 512; // Search within 512 bytes from nt!KiSystemCall64
    size_t patternSize = sizeof(kiSystemServiceRepeatPattern);

    for (size_t i = 0; i < searchRange - patternSize; i++) {
        uint8_t* currentAddress = (uint8_t*)(startAddress + i);

        // Check if the current memory matches the pattern
        if (CompareMemory(currentAddress, kiSystemServiceRepeatPattern, patternSize)) {
            return (uintptr_t)currentAddress;
        }
    }
    return 0x0;
}

uintptr_t LocateKeServiceDescriptorTableShadow(uintptr_t kiSystemServiceRepeat) {
    // Disassemble KiSystemServiceRepeat and find the RIP-relative reference to KeServiceDescriptorTableShadow
    // This offset would be determined based on the structure of the function.
    // In this example, assume it's 0x12 bytes into the function.

    return GetRipRelativeAddress((uint8_t*)kiSystemServiceRepeat, 0x12);  // Offset is just for example
}

// Main function to locate nt!KeServiceDescriptorTableShadow
uintptr_t GetServiceDescriptorTableShadow() {
    // Step 1: Read the MSR IA32_LSTAR to get the address of nt!KiSystemCall64
    uintptr_t kiSystemCall64 = ReadMsrLstar();

    // Step 2: Locate nt!KiSystemServiceRepeat by scanning or pattern matching
    uintptr_t ntKiSystemServiceRepeat = FindKiSystemServiceRepeat(kiSystemCall64);
    if (ntKiSystemServiceRepeat == 0) {
        kprintf("Failed to locate nt!KiSystemServiceRepeat\n");
        return 0;
    }

    // Step 3: Extract the RIP-relative address of nt!KeServiceDescriptorTableShadow
    uintptr_t keServiceDescriptorTableShadow = LocateKeServiceDescriptorTableShadow(ntKiSystemServiceRepeat);

    kprintf("nt!KeServiceDescriptorTableShadow is at:\n");

    return keServiceDescriptorTableShadow;
}

PVOID inithooking()
{
    UNICODE_STRING routineName;
    PVOID routineAddress = NULL;

    // Initialize the Unicode string with the target function name
    RtlInitUnicodeString(&routineName, L"KiSystemServiceStart");

    // Use MmGetSystemRoutineAddress to get the address of KiSystemServiceStart
    routineAddress = MmGetSystemRoutineAddress(&routineName);

    if (!routineAddress) {
        kprintf("Failed to locate KiSystemServiceStart!\n");
        return NULL;
    }

    kprintf("KiSystemServiceStart located at: %p\n", routineAddress);
    return routineAddress;
}
*/
PVOID GetProcAddress(PVOID ModuleBase, const char* FunctionName)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)ModuleBase + pDosHeader->e_lfanew);
    DWORD ExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ModuleBase + ExportDirRVA);

    DWORD* AddressOfFunctions = (DWORD*)((BYTE*)ModuleBase + pExportDirectory->AddressOfFunctions);
    DWORD* AddressOfNames = (DWORD*)((BYTE*)ModuleBase + pExportDirectory->AddressOfNames);
    WORD* AddressOfNameOrdinals = (WORD*)((BYTE*)ModuleBase + pExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        const char* ExportName = (const char*)((BYTE*)ModuleBase + AddressOfNames[i]);
        if (strcmp(ExportName, FunctionName) == 0)
        {
            DWORD FunctionRVA = AddressOfFunctions[AddressOfNameOrdinals[i]];
            return (PVOID)((BYTE*)ModuleBase + FunctionRVA);
        }
    }

    return NULL;
}

BOOLEAN CompareMemory(const unsigned char* data, const unsigned char* pattern, const char* mask) {
    for (; *mask; ++data, ++pattern, ++mask) {
        if (*mask == 'x' && *data != *pattern) {
            return FALSE;
        }
    }
    return TRUE;
}

// Function to scan memory range for pattern
PVOID ScanMemoryRange(PVOID startAddress, PVOID endAddress, const unsigned char* pattern, const char* mask) {
    unsigned char* currentAddress = (unsigned char*)startAddress;

    while (currentAddress < (unsigned char*)endAddress) {
        if (CompareMemory(currentAddress, pattern, mask)) {
            return currentAddress;
        }
        currentAddress++;
    }

    return NULL; // Pattern not found
}

typedef struct SystemServiceTable {
    UINT32* ServiceTable;

    UINT32* CounterTable;

    UINT32 ServiceLimit;

    UINT32* ArgumentTable;

} SST, *pSST;

PVOID GetTextSectionSize(PVOID kernelBase) {
    if (!kernelBase) {
        kprintf("Invalid kernel base address.\n");
        return 0;
    }

    // Get the DOS header (at the beginning of the image)
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)kernelBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        kprintf("Invalid DOS signature.\n");
        return 0;
    }

    // Get the NT headers using the e_lfanew field in the DOS header
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)kernelBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        kprintf("Invalid NT signature.\n");
        return 0;
    }

    // Get the section headers (right after the optional header)
    PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
    unsigned char pattern[] = {
0x4C, 0x8D, 0x15, 0xCC, 0xCC, 0xCC, 0xCC,
0x4C, 0x8D, 0x1D, 0xCC, 0xCC, 0xCC, 0xCC,
0xF7, 0x43, 0x78, 0x80, 0x00, 0x00, 0x00
    };

    char mask[] = "xxx????xxx????xxxxxxx";
    // Iterate over sections to find the ".text" section
    for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER section = &sectionHeaders[i];
        if ((sectionHeaders[i].Characteristics & IMAGE_SCN_CNT_CODE) && (sectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(sectionHeaders[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
        {
            PVOID start = (PVOID)((UINT64)sectionHeaders[i].VirtualAddress + (UINT64)(kernelBase));
            PVOID end = (PVOID)((UINT64)start + sectionHeaders[i].Misc.VirtualSize); //0xA1FCC0
            PVOID address = ScanMemoryRange(start, end, pattern, mask);
            
            if (address)
            {
                kprintf("Found to find .text section.\n");
                return address;
            }
        }
    }

    kprintf("Failed to find .text section.\n");
    return 0;
}
typedef struct _SERVICE_DESCRIPTOR_TABLE {
    unsigned int* ServiceTableBase;   // Pointer to the actual function addresses
    unsigned int* ServiceCounterTable; // Not used here (for counters/timers)
    unsigned int NumberOfServices;    // Total number of syscalls in the table
    unsigned char* ParamTableBase;    // Describes the number of parameters for each syscall
} SERVICE_DESCRIPTOR_TABLE, * PSERVICE_DESCRIPTOR_TABLE;

// Function to retrieve the address of the system call
PVOID GetSyscallAddress(PSERVICE_DESCRIPTOR_TABLE sdtAddress, ULONG syscallIndex) {
    // Validate if syscallIndex is within range
    if (syscallIndex >= sdtAddress->NumberOfServices) {
        return NULL;  // Invalid syscall index
    }

    // Return the function address from the table
    PVOID syscallFunctionAddress = (PVOID)(sdtAddress->ServiceTableBase[syscallIndex]);

    return syscallFunctionAddress;
}
uintptr_t ExtractAddressFromInstruction(uintptr_t instructionAddress) {
    // Buffer to hold the 7 bytes of the LEA instruction (3-byte opcode + 4-byte displacement)
    unsigned char instructionBytes[7];

    // Reading memory at the instruction address
    if (!MmIsAddressValid((PVOID)instructionAddress)) {
        DbgPrint("Invalid address: 0x%p\n", (PVOID)instructionAddress);
        return 0;
    }

    RtlCopyMemory(instructionBytes, (PVOID)instructionAddress, sizeof(instructionBytes));

    // The displacement is a 4-byte signed integer starting at byte 3 of the instruction
    int32_t displacement = *(int32_t*)&instructionBytes[3];

    // Calculate the address of the next instruction (RIP after LEA, 7 bytes long)
    uintptr_t nextInstruction = instructionAddress + 7;

    // Calculate the absolute target address
    uintptr_t absoluteAddress = nextInstruction + displacement;

    // Return the calculated absolute address
    return absoluteAddress;
}
BOOL bla()
{
    PVOID ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        kprintf("Memory access at too high IRQL.\n");
        return NULL;
    }
    PVOID foundAddress = GetTextSectionSize(ntoskrnlBase);

    if (foundAddress) {
        kprintf("Pattern found at address: %p\n", foundAddress);
        uintptr_t x = ExtractAddressFromInstruction((uintptr_t)foundAddress);
        kprintf("Pattern found at address: %p\n", x);

        //Dereference x to get KiServiceTable
        UINT64 KiServiceTable = *(UINT64*)x;
        kprintf("Pattern found at address: %p\n", KiServiceTable);
        //routineOffset = KiServiceTable+(4*syscall) //0x003f 
        UINT32 routineOffset = (UINT32)*(UINT64*)(KiServiceTable+(4* 0x0055)); //0x003f
        kprintf("Pattern found at address: %p\n", routineOffset);
        //routineOffset = 4 bytes

        //RoutineAddress = KiServiceTable + (routineOffset >>> 4)
        UINT64 RoutineAddress = KiServiceTable + (routineOffset >> 4);
        kprintf("Pattern found at address: %p\n", RoutineAddress);
        kprintf("Pattern found at address: %p\n",MmGetSystemRoutineAddress(&StringNtCreateFile));
        //THEY ARE THE SAME!!
        
        // 
        // 
        //PVOID result = GetSyscallAddress((PSERVICE_DESCRIPTOR_TABLE)foundAddress, 0x0055);
        //if (result != NULL)
        //{
        //    kprintf("Syscall found at address: %p\n", foundAddress);
        //    OriginalNtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&StringNtCreateFile);
        //    kprintf("Original found at address: %p\n", OriginalNtCreateFile);
        //}
    }
    else {
        kprintf("Pattern not found in the specified range.\n");
        return NULL;
    }
    return NULL;
    //pSST KeSST = //(pSST)foundAddress;

    
    //PVOID addr = GetProcAddress(ntoskrnlBase, "KiSystemCall64");
    //if (!addr)
        //return NULL;
    //kprintf("Base address of ntoskrnl.exe: %p\n", ntoskrnlBase);
    

    /*
    if (ntoskrnlBase) {
        kprintf("Base address of ntoskrnl.exe: %p\n", ntoskrnlBase);

        UINT64 searchRange = 0xFFFFFF; // Search within 512 bytes from nt!KiSystemCall64
        UINT64 patternSize = sizeof(kiSystemServiceRepeatPattern);

        for (size_t i = 0; i < searchRange - patternSize; i++) {
            UINT64* currentAddress = (UINT64*)(&ntoskrnlBase + i);

            // Check if the current memory matches the pattern
            if (CompareMemory(currentAddress, kiSystemServiceRepeatPattern, patternSize)) {
                kprintf("Foundpattern");
                return (uintptr_t)currentAddress;
            }
        }
        kprintf("Nofind");
    }
    else {
        kprintf("Failed to find ntoskrnl.exe.\n");
    }
    return NULL;*/
}

uintptr_t getSyscall(PVOID ntoskrnlBase, long syscallID)
{
    PVOID foundAddress = GetTextSectionSize(ntoskrnlBase);
    if (!foundAddress)
    {
        kprintf("Pattern not found in the specified range.\n");
        return NULL;
    }
    uintptr_t x = ExtractAddressFromInstruction((uintptr_t)foundAddress);
    if (!x)
    {
        kprintf("Couldn't extract");
        return NULL;
    }
    UINT64 KiServiceTable = *(UINT64*)x;
    if (!KiServiceTable)
    {
        kprintf("Couldn't resolve KiServiceTable");
        return NULL;
    }
    UINT32 routineOffset = (UINT32) * (UINT64*)(KiServiceTable + (4 * syscallID)); //0x003f
    if (!routineOffset)
    {
        kprintf("Couldn't resolve routineOffset");
        return NULL;
    }
    //routineOffset = 4 bytes

    //RoutineAddress = KiServiceTable + (routineOffset >>> 4)
    UINT64 RoutineAddress = KiServiceTable + (routineOffset >> 4);
    //kprintf("Pattern found at address: %p\n", RoutineAddress);
    return RoutineAddress;
}

BOOL locateSyscalls()
{
    PVOID ntoskrnl = GetKernelModuleBase("ntoskrnl.exe");
    uintptr_t result;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        kprintf("Memory access at too high IRQL.\n");
        return false;
    }
    result = getSyscall(ntoskrnl, 0x0055);
    if (!result)
    {
        kprintf("Resolve syscall failed\n");
        return false;
    }
    kprintf("Syscall found at address: %p\n", result);
    return true;
}

uintptr_t WaitForProcess()
{
    UINT64 processBase = Helper::find_eprocess(Helper::Config::targetNameTrimmed);
    if (!processBase)
    {
        kprintf("Process not found\n");
    }
    else
        kprintf("Found process\n");
    return processBase;
}

bool injector()
{
    return true;
}

typedef struct _PEB_LDR_DATA {
    char pad_0x0000[0x04]; //0 to 4
    UCHAR Initialized; //4 to 8
    char pad_0x0001[0x02]; //8 to 10
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _f_PEB {
    CHAR Reserved1[2];
    CHAR BeingDebugged;
    CHAR Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} f_PEB, * f_PPEB;

typedef struct _f_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderModuleList;
    char pad_0x0001[0x20];
    PVOID DllBase;
    char pad_0x0002[0x20];
    UNICODE_STRING BaseDllName;
} f_LDR_DATA_TABLE_ENTRY, * f_PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB32 {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;
    ULONG ProcessParameters;
    ULONG SubSystemData;
    ULONG ProcessHeap;
    ULONG FastPebLock;
    ULONG AtlThunkSListPtr;
    ULONG IFEOKey;
    ULONG CrossProcessFlags;
    ULONG UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32 {
    ULONG Length;
    UCHAR Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;


typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY32 HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _f_PEB_LDR_DATA {
    char pad_0x0001[0x10];
    LIST_ENTRY ModuleListLoadOrder;
} f_PEB_LDR_DATA, * f_PPEB_LDR_DATA;

extern "C"
{
    NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);
}
//NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(
    //IN PEPROCESS Process);

ULONG64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name) {
    f_PPEB pPeb = (f_PPEB)PsGetProcessPeb(proc);

    if (!pPeb)
        return NULL;

    KAPC_STATE state;

    KeStackAttachProcess(proc, &state);

    f_PPEB_LDR_DATA pLdr = (f_PPEB_LDR_DATA)pPeb->Ldr;
    if (!pLdr) {
        KeUnstackDetachProcess(&state);
        return NULL;
    }

    for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink;
        list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink) {
        f_PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, f_LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
        if (&pEntry->BaseDllName)
        {
            if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == 0) {
                ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
                KeUnstackDetachProcess(&state);
                return baseAddr;
            }
        }
    }

    KeUnstackDetachProcess(&state);
    return NULL;
}
/*
ULONG GetModuleBasex86(PEPROCESS proc, UNICODE_STRING module_name) {
    PPEB32 pPeb = (PPEB32)PsGetProcessWow64Process(proc);// get Process PEB for the x86 part, function is unexported and undoc

    if (!pPeb) {
        return 0; // failed
    }

    KAPC_STATE state;

    KeStackAttachProcess(proc, &state);

    PPEB_LDR_DATA32 pLdr = (PPEB_LDR_DATA32)pPeb->Ldr;

    if (!pLdr) {
        KeUnstackDetachProcess(&state);
        return 0; // failed
    }

    //UNICODE_STRING name;

    // loop the linked list
    for (PLIST_ENTRY32 list = (PLIST_ENTRY32)pLdr->InLoadOrderModuleList.Flink;
        list != &pLdr->InLoadOrderModuleList; list = (PLIST_ENTRY32)list->Flink) {
        PLDR_DATA_TABLE_ENTRY32 pEntry =
            CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
        // since the PEB is x86, the DLL is x86, and so the base address is in x86 (4 byte as compared to 8 byte)
        // and the UNICODE STRING is in 32 bit(UNICODE_STRING32), and because there is no viable conversion
        // we are just going to force everything in.
        // believe me it works.
        UNICODE_STRING DLLname;
        DLLname.Length = pEntry->BaseDllName.Length;
        DLLname.MaximumLength = pEntry->BaseDllName.MaximumLength;
        DLLname.Buffer = (PWCH)pEntry->BaseDllName.Buffer;

        if (RtlCompareUnicodeString(&DLLname, &module_name, TRUE) ==
            0) {
            ULONG baseAddr = pEntry->DllBase;
            KeUnstackDetachProcess(&state);
            return baseAddr;
        }
    }

    KeUnstackDetachProcess(&state);

    return 0; // failed
}
*/
UINT64 fetchDLLx64(PCWSTR dllName, PEPROCESS targetProcess)
{
    UNICODE_STRING DLLName_UNICODE;
    RtlInitUnicodeString(&DLLName_UNICODE, dllName);
    UINT64 BaseAddrr = GetModuleBasex64(targetProcess, DLLName_UNICODE);
    return BaseAddrr;
}


NTSTATUS ReadProcessMemory32(PEPROCESS targetProcess, PVOID sourceAddress, PINT32 outValue)
{
    KAPC_STATE apcState;
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        // Attach to the address space of the target process
        KeStackAttachProcess(targetProcess, &apcState);

        // Probe the memory address to ensure it's valid before reading (if user-mode memory)
        ProbeForRead(sourceAddress, sizeof(INT32), sizeof(UCHAR));

        // Read the INT32 from the source address
        *outValue = *(PINT32)sourceAddress;

        // Detach from the process
        KeUnstackDetachProcess(&apcState);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode(); // Handle any exception (e.g., invalid address access)
        KeUnstackDetachProcess(&apcState);  // Ensure detach happens even on failure
    }

    return status;
}

_RTL_BALANCED_NODE* GetVADEntry(HANDLE processHandle, PVOID baseAddress, long procid) {
    // 1. Get EPROCESS of the target process
    PEPROCESS targetEprocess;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)procid, &targetEprocess);
    if (!NT_SUCCESS(status)) {
        kprintf("no handle");
        return NULL; // Failed to get the process handle
    }

    // 2. Access the VadRoot (usually of type _RTL_AVL_TREE)
    kprintf("root:");
    _RTL_AVL_TREE* vadRoot = (_RTL_AVL_TREE*)((UINT64)targetEprocess + 0x7d8);

    // 3. Traverse the AVL tree to find the VAD entry for the baseAddress
    kprintf("curnode:");
    _RTL_BALANCED_NODE* currentNode = vadRoot->Root;
    kprintf("pagenum:");
    ULONG_PTR vpnBase = (ULONG_PTR)baseAddress >> PAGE_SHIFT; // Convert address to page number
    kprintf("itr:");
    while (currentNode != NULL) {
        _MMVAD_SHORT* vadEntry = CONTAINING_RECORD(currentNode, _MMVAD_SHORT, VadNode);

        if (vpnBase < vadEntry->StartingVpn) {
            currentNode = currentNode->Left;  // Traverse left
        }
        else if (vpnBase > vadEntry->EndingVpn) {
            currentNode = currentNode->Right; // Traverse right
        }
        else {
            // Found the VAD entry for the given base address
            return currentNode;  // Cast to your VAD_ENTRY type
        }
    }

    // If we reach here, no VAD entry was found for this address
    return NULL;
}

void UnlinkOrModifyVAD(_RTL_BALANCED_NODE* vadEntry) {
    if (!vadEntry) return;

    // Option A: Modify the VAD entry to mask the protection
    // vadEntry->u.VadFlags.Protection = PAGE_READONLY;  // Change the protection to read-only

    _RTL_BALANCED_NODE* parent = (_RTL_BALANCED_NODE*)(vadEntry->ParentValue & ~0x3); // Mask out metadata bits

    if (!parent) {
        // The VAD entry is the root of the tree, can't unlink
        kprintf("VAD entry is root");
        return;
    }

    if (parent->Left == vadEntry) {
        // Replace the parent's left child with vadEntry's left or right child
        parent->Left = vadEntry->Left ? vadEntry->Left : vadEntry->Right;
    }
    else if (parent->Right == vadEntry) {
        // Replace the parent's right child with vadEntry's left or right child
        parent->Right = vadEntry->Left ? vadEntry->Left : vadEntry->Right;
    }

    // Optionally: Set the child's parent value to maintain tree integrity if needed
    if (parent->Left) {
        parent->Left->ParentValue = (uintptr_t)parent;
    }
    else if (parent->Right) {
        parent->Right->ParentValue = (uintptr_t)parent;
    }

    kprintf("Unlinked VAD entry");
}

void ModifyVADEntry(HANDLE processHandle, PVOID baseAddress, SIZE_T regionSize, long procid) {
    // Get the VAD entry of the allocated memory region
    _RTL_BALANCED_NODE* vadEntry = GetVADEntry(processHandle, baseAddress, procid);

    // Unlink the VAD entry from the VAD tree or modify it to point to something benign
    
    if (!vadEntry)
    {
        kprintf("Couldn't find vad\n");
        return;
    }
    

    UnlinkOrModifyVAD(vadEntry);

    vadEntry = GetVADEntry(processHandle, baseAddress, procid);

    if (vadEntry)
    {
        kprintf("VAD unlink failed\n");
    }
    kprintf("VAD unlinked\n");
    // This function is highly kernel-specific and requires working with undocumented VAD structures.
}

PVOID UserModeBaseAddress = NULL;
PMDL Mdl = NULL;
PVOID KernelModeAddress = NULL;

NTSTATUS StealthyAllocateMemory(long targetProcessHandle, PVOID* MappedVirtualAddress, SIZE_T regionSize) {
    
    PEPROCESS targetProcess;
    NTSTATUS status;

    // Step 1: Lookup the process by ID
    status = PsLookupProcessByProcessId((HANDLE)targetProcessHandle, &targetProcess);
    if (!NT_SUCCESS(status)) {
        kprintf("PsLookupProcessByProcessId failed: 0x%x\n", status);
        return status;
    }

    HANDLE processHandle;

    // Step 2: Open the process object
    status = ObOpenObjectByPointer(targetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &processHandle);
    if (!NT_SUCCESS(status)) {
        kprintf("ObOpenObjectByPointer failed: 0x%x\n", status);
        return status;
    }
    HANDLE sectionHandle = NULL;
    LARGE_INTEGER sectionSize;
    PVOID sectionBaseAddress = NULL;
    SIZE_T viewSize = 0;

    // Initialize the section size
    sectionSize.QuadPart = regionSize;
    status = ZwCreateSection(
        &sectionHandle,
        SECTION_ALL_ACCESS,
        NULL,           // Object attributes
        &sectionSize,   // Size of the section
        PAGE_READWRITE, // Memory protection
        SEC_COMMIT,     // Commit memory immediately
        NULL            // No file handle (anonymous memory)
    );
    if (!NT_SUCCESS(status)) {
        kprintf("ZwCreateSection failed: 0x%x\n", status);
        return status;
    }
    status = ZwMapViewOfSection(
        sectionHandle,
        processHandle, // Map into the target process
        MappedVirtualAddress,     // Output: address in user mode
        0L,                  // Zero bits
        regionSize,          // Committed size
        NULL,                // No offset
        &viewSize,           // View size (input/output)
        ViewUnmap,           // Unmap when handle is closed
        0L,                  // Allocation type
        PAGE_READWRITE       // Protection
    );
    if (!NT_SUCCESS(status)) {
        kprintf("ZwMapViewOfSection failed: 0x%x\n", status);
        return status;
    }
    // Step 3: Allocate virtual memory in the target process
    
    kprintf("Success\n");
    MEMORY_BASIC_INFORMATION memoryInfo;
    SIZE_T returnLength;
    status = ZwQueryVirtualMemory(
        processHandle,   // Handle to the target process
        *MappedVirtualAddress,      // Base address of the mapped memory
        MemoryBasicInformation,
        &memoryInfo,
        sizeof(memoryInfo),
        &returnLength
    );

    

    if (NT_SUCCESS(status)) {
        if (memoryInfo.State == MEM_COMMIT) {
            // Memory is committed and accessible
            kprintf("committed\n");
        }
        else {
            // Memory is not committed, handle error
            kprintf("not commited\n");
            return STATUS_UNSUCCESSFUL;
        }
    }
    else {
        // Handle error in querying virtual memory
        kprintf("queryfailed\n");
        kprintf("ZwMapViewOfSection failed: 0x%x\n", status);
        return status;
    }

    KAPC_STATE apcState;
    SIZE_T pageSize = PAGE_SIZE;
    KeStackAttachProcess(targetProcess, &apcState);

    __try {
        // Step 2: Access (touch) each page in the user-mode mapped memory
        for (SIZE_T offset = 0; offset < regionSize; offset += pageSize) {
            // Safely touch the page by reading or writing
            *(volatile PBYTE)((UINT64)*MappedVirtualAddress + offset) = 0;  // Write to each page to force it into physical memory
        }

        kprintf("[+] Successfully touched user-mode pages from kernel.\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        kprintf("[-] Exception while touching user-mode pages: 0x%x\n", GetExceptionCode());
        // Handle access violation or page faults
        KeUnstackDetachProcess(&apcState);
        return GetExceptionCode();
    }

    // Step 3: Detach from the process's address space
    KeUnstackDetachProcess(&apcState);

    return STATUS_SUCCESS;
   /* PEPROCESS targetProcess;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)targetProcessHandle, &targetProcess);

    if (!NT_SUCCESS(status)) {
        kprintf("Failed to get EPROCESS from PID. NTSTATUS: 0x%08X\n", status);
        return STATUS_ABANDONED;
    }
    HANDLE processHandle;
    status = ObOpenObjectByPointer(targetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, UserMode, &processHandle);

    if (!NT_SUCCESS(status)) {
        kprintf("Failed to get process handle. NTSTATUS: 0x%08X\n", status);
        return STATUS_ABANDONED;
    }
    PVOID virtualMemory = NULL;
    PMDL mdl = NULL;
    PVOID mappedMemory = NULL;


    if (processHandle == NULL) {
        kprintf("Invalid handle passed to ZwAllocateVirtualMemory.\n");
        return STATUS_INVALID_HANDLE;
    }

   


    // 1. Allocate virtual memory
    status = ZwAllocateVirtualMemory(processHandle,
        &virtualMemory,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        kprintf("ZwAllocateVirtualMemory failed: 0x%x\n", status);
        return status;
    }

    kprintf("Allocated virtual memory at: %p\n", virtualMemory);

    // 2. Allocate MDL to describe the pages
    mdl = IoAllocateMdl(virtualMemory, (ULONG)regionSize, FALSE, FALSE, NULL);
    if (!mdl) {
        kprintf("IoAllocateMdl failed\n");
        ZwFreeVirtualMemory(ZwCurrentProcess(), &virtualMemory, &regionSize, MEM_RELEASE);  // Corrected line
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        // 3. Lock the pages in physical memory
        MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        kprintf("MmProbeAndLockPages failed\n");
        IoFreeMdl(mdl);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &virtualMemory, &regionSize, MEM_RELEASE);  // Corrected line
        return GetExceptionCode();
    }

    // 4. Map locked pages into virtual address space
    mappedMemory = MmMapLockedPagesSpecifyCache(mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (!mappedMemory) {
        kprintf("MmMapLockedPagesSpecifyCache failed\n");
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &virtualMemory, &regionSize, MEM_RELEASE);  // Corrected line
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    kprintf("Mapped physical memory to virtual address: %p\n", mappedMemory);

    // Return the mapped virtual address to the caller
    *MappedVirtualAddress = mappedMemory;

    return STATUS_SUCCESS;
    */

    /*
    PMDL mdl = IoAllocateMdl(baseAddress, (ULONG)regionSize, FALSE, FALSE, NULL);
    if (!mdl) {
        kprintf("Failed to allocate MDL\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
    PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (!mappedAddress) {
        kprintf("Failed to map locked pages\n");
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*ULONG numPages = (ULONG)regionSize >> PAGE_SHIFT; // Convert size to number of pages

    // Allocate the READ_LIST structure, large enough for the number of pages to prefetch
    PREAD_LIST readList = (PREAD_LIST)ExAllocatePoolWithTag(NonPagedPool,
        sizeof(READ_LIST) + sizeof(FILE_SEGMENT_ELEMENT) * numPages, 'rdlt');
    if (!readList) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    readList->FileObject = NULL; // Prefetching memory, not file-backed
    readList->NumberOfEntries = numPages;
    readList->IsImage = FALSE; // Not prefetching an image file

    // Initialize the List array (FILE_SEGMENT_ELEMENT)
    for (ULONG i = 0; i < numPages; i++) {
        readList->List[i].Buffer = (PVOID)((ULONG_PTR)baseAddress + (i * PAGE_SIZE));
    }
    // Call MmPrefetchPages with the read list
    status = MmPrefetchPages(1, &readList);
    if (status != STATUS_SUCCESS)
    {
        kprintf("Prefetch failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Cleanup
    ExFreePoolWithTag(readList, 'rdlt');*/

    // Step 2: Modify the VAD entry to hide the allocation (high-level concept, requires detailed VAD manipulation code)
    //ModifyVADEntry(processHandle, *baseAddress, regionSize, (long)targetProcessHandle);

    // Step 3: Modify the PTE to make the memory executable at hardware level, but show as non-executable
    //ModifyPTE(*baseAddress, PAGE_EXECUTE_READWRITE, PAGE_READWRITE);

    // Return success if all steps are successful
    //kprintf("Memory successfully allocated at base address: %p in target process.\n", *baseAddress);
}

NTSTATUS ReadFileFromDisk(PCWSTR filePath, PVOID* buffer, PSIZE_T bufferSize) {
    UNICODE_STRING unicodeFilePath;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;
    PVOID fileBuffer;
    SIZE_T fileSize;
    LARGE_INTEGER byteOffset;
    FILE_STANDARD_INFORMATION fileInformation;

    // Initialize file path as a UNICODE_STRING
    RtlInitUnicodeString(&unicodeFilePath, filePath);

    // Initialize OBJECT_ATTRIBUTES for the file
    InitializeObjectAttributes(&objectAttributes, &unicodeFilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Open the file using ZwCreateFile
    status = ZwCreateFile(&fileHandle, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

    if (!NT_SUCCESS(status)) {
        kprintf("Failed to open file: %wZ, Status: 0x%08X\n", &unicodeFilePath, status);
        return status;
    }

    // Query the file size
    status = ZwQueryInformationFile(fileHandle, &ioStatusBlock, &fileInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        kprintf("Failed to query file size. Status: 0x%08X\n", status);
        ZwClose(fileHandle);
        return status;
    }

    fileSize = (SIZE_T)fileInformation.EndOfFile.QuadPart;
    *bufferSize = fileSize;

    // Allocate memory for the file content in non-paged pool
    fileBuffer = ExAllocatePoolWithTag(NonPagedPool, fileSize, 'FILE');  // 'FILE' is just a custom tag for memory tracking
    if (!fileBuffer) {
        kprintf("Failed to allocate memory for file content.\n");
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Read the file content
    byteOffset.QuadPart = 0;  // Start reading from the beginning of the file
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, fileBuffer, (ULONG)fileSize, &byteOffset, NULL);

    if (!NT_SUCCESS(status)) {
        kprintf("Failed to read file content. Status: 0x%08X\n", status);
        ExFreePoolWithTag(fileBuffer, 'FILE');
        ZwClose(fileHandle);
        return status;
    }

    // Set the output buffer
    *buffer = fileBuffer;

    // Close the file handle
    ZwClose(fileHandle);

    return STATUS_SUCCESS;
}

extern "C" __declspec (dllimport)
NTSTATUS NTAPI MmCopyVirtualMemory
(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

NTSTATUS MapHeaders(PVOID dllData, PVOID allocatedMemory) {

    if (allocatedMemory == NULL) {
        kprintf("Invalid allocatedMemory pointer.\n");
        return STATUS_UNSUCCESSFUL;
    }

    if (dllData == NULL)
    {
        kprintf("Invalid dllData\n");
        return STATUS_UNSUCCESSFUL;

    }
    if ((ULONG_PTR)allocatedMemory % sizeof(PVOID) != 0) {
        kprintf("Allocated memory is not aligned properly.\n");
        return STATUS_DATATYPE_MISALIGNMENT;
    }


    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllData + dosHeader->e_lfanew);
    SIZE_T headersSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    PEPROCESS targetProcess = (PEPROCESS)Helper::find_eprocess(Helper::Config::targetNameTrimmed);
    PEPROCESS sourceProcess = PsGetCurrentProcess();
    if (targetProcess == NULL) {
        kprintf("Invalid targetProcess pointer.\n");
        return STATUS_UNSUCCESSFUL;
    }
    if (sourceProcess == NULL) {
        kprintf("Invalid sourceProcess pointer.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Copy headers into the allocated memory in the target process
    NTSTATUS status = MmCopyVirtualMemory(sourceProcess,
        dllData,                // Source DLL data
        targetProcess,          // Target process handle
        allocatedMemory,        // Destination memory in target process
        headersSize,            // Size of headers
        KernelMode,             // KernelMode copy
        nullptr);               // Bytes copied
    return status;
}

NTSTATUS MapSections(PVOID dllData, PVOID allocatedMemory) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllData + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    // Loop through all sections
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
        PVOID sectionSource = (PVOID)((BYTE*)dllData + sectionHeader->PointerToRawData);
        PVOID sectionDestination = (PVOID)((BYTE*)allocatedMemory + sectionHeader->VirtualAddress);
        SIZE_T sectionSize = sectionHeader->SizeOfRawData;
        PEPROCESS targetProcess = (PEPROCESS)Helper::find_eprocess(Helper::Config::targetNameTrimmed);
        // Copy section data to allocated memory in target process
        NTSTATUS status = MmCopyVirtualMemory(PsGetCurrentProcess(),
            sectionSource,           // Source section
            targetProcess,           // Target process handle
            sectionDestination,      // Destination address in target process
            sectionSize,             // Section size
            KernelMode,              // KernelMode copy
            nullptr);                // Bytes copied
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS ResolveImports(PVOID dllData, PVOID allocatedMemory) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllData + dosHeader->e_lfanew);

    // Get the import directory from the PE headers
    PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0) {
        return STATUS_SUCCESS;  // No imports to resolve
    }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)allocatedMemory + importDir->VirtualAddress);

    // Iterate over the import descriptor entries
    while (importDesc->Name) {
        PCHAR moduleName = (PCHAR)((BYTE*)allocatedMemory + importDesc->Name);

        // Resolve the module's base address (equivalent to LoadLibrary)
        PVOID moduleBase = nullptr;

        moduleBase = GetKernelModuleBase(moduleName); //(moduleName, &moduleBase);
        if (!moduleBase){
            return STATUS_ABANDONED;
        }

        // Resolve function addresses for this module
        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)allocatedMemory + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)allocatedMemory + importDesc->FirstThunk);
        while (origThunk->u1.AddressOfData) {
            PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)allocatedMemory + origThunk->u1.AddressOfData);

            // Get the function address from the module
            PVOID funcAddr = GetProcAddress(moduleBase, importByName->Name);
            if (!funcAddr) {
                return STATUS_PROCEDURE_NOT_FOUND;
            }

            thunk->u1.Function = (ULONG_PTR)funcAddr;  // Write the resolved function address
            origThunk++;
            thunk++;
        }

        importDesc++;
    }
    return STATUS_SUCCESS;
}

NTSTATUS ResolveRelocations(PVOID dllData, PVOID allocatedMemory, ULONG_PTR actualBaseAddress) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dllData + dosHeader->e_lfanew);

    ULONG_PTR delta = actualBaseAddress - ntHeaders->OptionalHeader.ImageBase;

    // If no relocation is needed, return early
    if (delta == 0 || ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) {
        return STATUS_SUCCESS;
    }

    // Locate the base relocation table
    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)allocatedMemory + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    while (reloc->VirtualAddress) {
        WORD* relocationData = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
        ULONG count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        // Process each relocation entry
        for (ULONG i = 0; i < count; i++) {
            if (relocationData[i] >> 12 == IMAGE_REL_BASED_HIGHLOW) {
                PULONG_PTR patchAddr = (PULONG_PTR)((BYTE*)allocatedMemory + reloc->VirtualAddress + (relocationData[i] & 0xFFF));
                *patchAddr += delta;  // Adjust the address by the delta
            }
        }

        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }

    return STATUS_SUCCESS;
}

NTSTATUS AllocateAndMapMemoryInUsermode(
    HANDLE ProcessHandle,   // Target process handle
    PVOID* UserModeAddress, // Pointer to the base address (output)
    SIZE_T Size,            // Size of the memory region
    PVOID* KernelAddress    // Pointer to mapped kernel address (output)
)
{
    // Step 1: Allocate memory in the usermode process
    SIZE_T RegionSize = Size;
    NTSTATUS status = ZwAllocateVirtualMemory(
        ProcessHandle,
        UserModeAddress,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(status)) return status;

    // Step 2: Lock the allocated pages in memory
    Mdl = IoAllocateMdl(*UserModeAddress, (ULONG)Size, FALSE, FALSE, NULL);
    if (!Mdl) return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        MmProbeAndLockPages(Mdl, UserMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(Mdl);
        return STATUS_UNSUCCESSFUL;
    }

    // Step 3: Map the locked pages in kernel space
    *KernelAddress = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);
    if (!*KernelAddress) {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}
typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

extern "C"
{

    NTSYSAPI
        NTSTATUS
        NTAPI
        RtlCreateUserThread(
            _In_ HANDLE ProcessHandle,
            _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
            _In_ BOOLEAN CreateSuspended,
            _In_opt_ ULONG ZeroBits,
            _In_opt_ SIZE_T MaximumStackSize,
            _In_opt_ SIZE_T CommittedStackSize,
            _In_ PUSER_THREAD_START_ROUTINE StartAddress,
            _In_opt_ PVOID Parameter,
            _Out_opt_ PHANDLE ThreadHandle,
            _Out_opt_ PCLIENT_ID ClientId
        );
}


NTSTATUS init()
{
    CHAR                streamRead[16];
    UNICODE_STRING      uniName;
    OBJECT_ATTRIBUTES   objAttr;
    NTSTATUS            ntstatus;
    HANDLE              handle;
    IO_STATUS_BLOCK     ioStatusBlock;
    LARGE_INTEGER       byteOffset;

    (void)streamRead;
    (void)uniName;
    (void)objAttr;
    (void)ntstatus;
    (void)handle;
    (void)ioStatusBlock;
    (void)byteOffset;

    
    PVOID dll = NULL;
    SIZE_T dllSizeRaw = NULL;

    PVOID k32 = NULL;
    SIZE_T k32SizeRaw = NULL;

    kprintf("[+] Driver\n");

    if (!NT_SUCCESS(Helper::GetWindowsVersion())) {
        kprintf("[x] Windows version not compatible\n");
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(Helper::Config::CreateConfig("notepad.exe", false, true))) {
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(ReadFileFromDisk(L"\\??\\C:\\Users\\Billy\\Desktop\\CS2-sxy.dll", &dll, &dllSizeRaw))) {
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(ReadFileFromDisk(L"\\??\\C:\\Windows\\System32\\kernel32.dll", &k32, &k32SizeRaw))) {
        return STATUS_UNSUCCESSFUL;
    }
    //if (!NT_SUCCESS(Helper::HideSelf())) {
        //return STATUS_UNSUCCESSFUL;
    //}
    //if (!NT_SUCCESS(Helper::ResolveSyscalls())) {
        //return STATUS_UNSUCCESSFUL;
    //}



    PEPROCESS target = (PEPROCESS)Helper::PollUntilProcess(); //Seems to sometimes work when process is closed..
    KAPC_STATE state;
    PVOID ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
    PVOID startAddress = NULL;
    PVOID k32startAddress = NULL;
    if (!NT_SUCCESS(sys::setupDll(target, dll, dllSizeRaw, &startAddress, ntoskrnlBase))) 
        return STATUS_UNSUCCESSFUL;

    //if (!NT_SUCCESS(sys::setupDll(target, k32, k32SizeRaw, &k32startAddress, ntoskrnlBase)))
        //return STATUS_UNSUCCESSFUL;

    kprintf("[++] DLL successfully created, starting execution\n");

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)dll + dosHeader->e_lfanew);
    
    PVOID entryPoint = (PVOID)((UINT64)startAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    kprintf("Start addr %p\n", entryPoint);
    HANDLE hThread;
    RtlCreateUserThread(target, NULL, FALSE, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)entryPoint, NULL, &hThread, NULL); // Start Thread


    kprintf("[++] Success\n");
    return STATUS_SUCCESS;

    //Finish resolve imports

    //Trip entry point 

    //Change "22H2" to "offsets"

    //Quality check HideSelf

    /* PVOID ntoskrnl = GetKernelModuleBase("ntoskrnl.exe");
    uintptr_t result;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        kprintf("Memory access at too high IRQL.\n");
        return false;
    }

    //KeQueryPerformanceCounter
    result = getSyscall(ntoskrnl, 0x0031);
    if (result != NULL) {
        kprintf("Syscall found at address: %p\n", result);
        OriginalNtQueryPerformanceCounter = (NtQueryPerformanceCounter_t)result;
    }
    // NtQuerySystemTime
    result = getSyscall(ntoskrnl, 0x005a);
    if (result != NULL) {
        kprintf("Syscall found at address: %p\n", result);
        OriginalNtQuerySystemTime = (NtQuerySystemTime_t)result;
    }
    // NtSetTimerResolution
    result = getSyscall(ntoskrnl, 0x01b2);
    if (result != NULL) {
        kprintf("Syscall found at address: %p\n", result);
        OriginalNtSetTimerResolution = (NtSetTimerResolution_t)result;
    }
    // NtQueryTimerResolution
    result = getSyscall(ntoskrnl, 0x0163);
    if (result != NULL) {
        kprintf("Syscall found at address: %p\n", result);
        OriginalNtQueryTimerResolution = (NtQueryTimerResolution_t)result;
    }
    // ZwWaitForSingleObject
    result = getSyscall(ntoskrnl, 0x0004);
    if (result != NULL) {
        kprintf("Syscall found at address: %p\n", result);
        OriginalZwWaitForSingleObject = (ZwWaitForSingleObject_t)result;
    }
    // ZwDelayExecution
    result = getSyscall(ntoskrnl, 0x0034);
    if (result != NULL) {
        kprintf("Syscall found at address: %p\n", result);
        OriginalZwDelayExecution = (ZwDelayExecution_t)result;
    }
    IfhInitialize2(SyscallStub);*/
    

    //kprintf("[++] Success\n");
    //return STATUS_SUCCESS;



    /*
    if (!NT_SUCCESS(sys::StealthAlloc(target, &memAllocationBase, dllSize))) { //Will also touch pages
        return STATUS_UNSUCCESSFUL;
    }

    kprintf("memory allocated at %p\n", memAllocationBase);

    if (!NT_SUCCESS(sys::MapDll(target, memAllocationBase, dll, dllSize))) {
        return STATUS_UNSUCCESSFUL;
    }
    KAPC_STATE state;
    KeStackAttachProcess(target, &state);
    if (!NT_SUCCESS(sys::ResolveImports(memAllocationBase, target)))
    {
        kprintf("[+] Dave failed\n");
        KeUnstackDetachProcess(&state);
        return STATUS_UNSUCCESSFUL;
    }
    KeUnstackDetachProcess(&state);*/


    //Unresolved imports

    //parse the IMAGE_IMPORT_DESCRIPTOR
    //e.g., GetProcAddress from kernel32.dll

    //Relocations table



    /*
    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE apcState;
    PVOID DllEntryPoint = NULL;

    // 1. Parse the DLL PE header to locate the entry point
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dll;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)dll + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Get the address of the entry point (AddressOfEntryPoint from OptionalHeader)
    ULONG entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    if (entryPointRVA == 0) {
        return STATUS_INVALID_ADDRESS;
    }

    DllEntryPoint = (PVOID)((PUCHAR)dll + entryPointRVA);

    // 2. Attach to the target process to run in user context
    KeStackAttachProcess(target, &apcState);

    __try {
        // 3. Call the entry point (DllMain) in the context of the target process
        typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

        DLLMAIN dllMain = (DLLMAIN)DllEntryPoint;
        //BOOL result = dllMain((HINSTANCE)dll, DLL_PROCESS_ATTACH, NULL);

        //if (!result) {
            //status = STATUS_UNSUCCESSFUL;
        //}
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    HANDLE threadHandle = NULL;
    CLIENT_ID clientId;
    RtlCreateUserThread(ZwCurrentProcess(), NULL, FALSE, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)DllEntryPoint, NULL, &threadHandle, &clientId);

    // 4. Detach from the process after executing the entry point
    KeUnstackDetachProcess(&apcState);

    */




    //if (!NT_SUCCESS(sys::TriggerDllStart())) {
    //    return STATUS_UNSUCCESSFUL;
    //}











    //kprintf("Mem begins at : %p\n", memAllocationBase);
    //kprintf("The value of size_t variable is: %zu\n", dllSize);


    /*PVOID Destination = ExAllocatePoolWithTag(NonPagedPool, 600, 'tag1');
    long procID = *(long*)((UINT64)target + 0x440);
    Mem::readMem(procID, memAllocationBase, Destination, 60);
    for (int i = 0; i < 50; i++) {
        kprintf("Byte %d: 0x%02X\n", i, ((PUCHAR)Destination)[i]);
    }
    Mem::writeMem(procID, memAllocationBase, Destination, 60);
    Mem::readMem(procID, memAllocationBase, Destination, 500); */

    


    //if config > MonitorSyscalls()
    //MapDll(basicDll)
    
    //MapDll()
    //TriggerStart()

    //OR

    //Kernel stuff

    
    
    //if (!Helper::fetchWindowsVersion())
        //return STATUS_ABANDONED;

    /*if (!Helper::Config::init("notepad.exe", false, true)) //Target our game (we could take this as an arg from the loader)
        return STATUS_ABANDONED;

    //if (!Helper::setupDriver())
        //return STATUS_ABANDONED;

    if (Helper::Config::acIsUsermode)
        if (!locateSyscalls())
        {
            return STATUS_ABANDONED;
        }

    kprintf("[++] Waiting for target\n");

    UINT64 base;
    base = WaitForProcess(); //Wrap this
    if (!base)
    {
       // Helper::shutdownDriver();
        kprintf("Driver shut down\n");
        return STATUS_SUCCESS;
    }

    if (NT_SUCCESS(status)) {
        kprintf("Successfully read DLL. Size: %llu bytes\n", dllSize);
        // You can now proceed with your manual mapping steps, using dllData as your DLL in-memory representation.
    }
    else {
        kprintf("Failed to read the DLL file. Status: 0x%08X\n", status);
        return STATUS_SUCCESS;
    }

    if (Helper::Config::cheatIsInternal)
    {
        PVOID mem = sys::StealthAlloc()
        //mem = AllocateMem()
        // enableSyscallMonitor(mem)
        //inject(mem, dll)
        //triggerEntryPoint()


        PVOID allocatedMem = NULL;
        long procID = *(long*)(base + 0x440);

        if (STATUS_SUCCESS != StealthyAllocateMemory(procID, &allocatedMemory, dllSize)) //Do not allow page out
        {
            return STATUS_SUCCESS;
        }
        kprintf("Memory successfully allocated at base address: %p in target process.\n", allocatedMemory);


        PVOID Destination = ExAllocatePoolWithTag(NonPagedPool, 600, 'tag1');
        if (!Destination) {
            kprintf("[-] Failed to allocate destination buffer in kernel space.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        */
        /*kprintf("Reading mem\n");
        Mem::readMem(procID, allocatedMemory, Destination, 60);
        //kprintf("Writing mem\n");
        for (int i = 0; i < 50; i++) {
            kprintf("Byte %d: 0x%02X\n", i, ((PUCHAR)Destination)[i]);
        }
        RtlFillMemory(Destination, 50, 0xAB);
        Mem::writeMem(procID, allocatedMemory, Destination, 60);
        //kprintf("Reading mem\n");
        RtlFillMemory(Destination, 50, 0x0);
        Mem::readMem(procID, allocatedMemory, Destination, 60);
        for (int i = 0; i < 50; i++) {
            kprintf("Byte %d: 0x%02X\n", i, ((PUCHAR)Destination)[i]);
        }*/

        
        /*
        else
        {
            PEPROCESS targetProcess;

            // Step 1: Lookup the process by ID
            status = PsLookupProcessByProcessId((HANDLE)procID, &targetProcess);
            if (!NT_SUCCESS(status)) {
                kprintf("PsLookupProcessByProcessId failed: 0x%x\n", status);
                return status;
            }

            HANDLE processHandle;

            // Step 2: Open the process object
            status = ObOpenObjectByPointer(targetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &processHandle);
            SIZE_T bytesCopied;
            status  = MmCopyVirtualMemory(targetProcess, allocatedMemory, PsGetCurrentProcess(), &buffer, sizeof(buffer), KernelMode, &bytesCopied);
            if (!NT_SUCCESS(status)) {
                kprintf("MmCopyVirtualMemory failed: 0x%x\n", status);
                return status;
            }
            else
            {
                for (size_t i = 0; i < bytesRead; i++) {
                    kprintf("%02X ", buffer[i]);
                }
            }
        }
        */

        
        /*
        if (STATUS_SUCCESS != StealthyAllocateMemory(procID, &allocatedMemory, dllSize))
        {
            kprintf("Allocating buffer failed\n");
            return STATUS_SUCCESS;
        }
        kprintf("Allocated buffer\n");
        kprintf("Memory successfully allocated at base address: %p in target process.\n", allocatedMemory);
        //Enable syscall hooks to protect allocation
        //initializeHooks();
        
        //Create copy of client.dll etc

        //Copy DLL into buffer
        //UINT64 baseaddy;
        //INT32 buffer;
        PEPROCESS targProc;
        PsLookupProcessByProcessId((HANDLE)procID, &targProc);

        UCHAR buffer[64] = { 0 };  // Adjust buffer size as needed, here it's 64 bytes
        SIZE_T bytesRead = 60;
        kprintf("Before write:\n");
        Mem::readMem(procID, (UINT64)allocatedMemory, &buffer, sizeof(buffer));
        for (size_t i = 0; i < bytesRead; i++) {
            kprintf("%02X ", buffer[i]);
        }
        kprintf("\nWriting:\n");
        Mem::writeMem(procID, (UINT64)allocatedMemory, &dllData, 0x100);
        for (size_t i = 0; i < bytesRead; i++) {
            kprintf("%02X ", ((UCHAR*)dllData)[i]);
        }

        kprintf("\nAfter write:\n");
        Mem::readMem(procID, (UINT64)allocatedMemory, &buffer, sizeof(buffer));
        for (size_t i = 0; i < bytesRead; i++) {
            kprintf("%02X ", buffer[i]);
        }


        PEPROCESS targProcXCX;
        UINT64 baseaddyXCX;
        INT32 bufferXCX = NULL;
        PsLookupProcessByProcessId((HANDLE)procID, &targProcXCX);
        baseaddyXCX = fetchDLLx64(L"mrmcorer.dll", targProcXCX);
        if (baseaddyXCX == NULL)
        {
            kprintf("baseaddyXCX is null\n");
            return STATUS_ABANDONED;
        }
        Mem::readMem(procID, baseaddyXCX, &bufferXCX, sizeof(bufferXCX));
        kprintf("Read value: %d\n", bufferXCX);
        */

        /*
        // Step 1: Map headers into the target process
        status = MapHeaders(dllData, allocatedMemory);
        if (!NT_SUCCESS(status)) {
            kprintf("map fail");
            return status;
        }
        kprintf("Mapped headers\n", status);
        // Step 2: Map sections into the target process
        status = MapSections(dllData, allocatedMemory);
        if (!NT_SUCCESS(status)) {
            kprintf("map fail2");
            return status;
        }
        kprintf("Mapped sections\n", status);
        // Step 3: Resolve imports after mapping
        status = ResolveImports(dllData, allocatedMemory);
        if (!NT_SUCCESS(status)) {
            kprintf("map fail3");
            return status;
        }
        kprintf("Resolved imports\n", status);
        // Step 4: Resolve relocations after mapping
        status = ResolveRelocations(dllData, allocatedMemory, (ULONG_PTR)allocatedMemory);
        if (!NT_SUCCESS(status)) {
            kprintf("map fail4");
            return status;
        }
        kprintf("Resolved relocations\n", status);*/
        

        //Call entry point
    //}
    //else //cheatIsExternal
    //{
        //
    //}







    //https://github.com/charliewolfe/Stealthy-Kernelmode-Injector?tab=readme-ov-file

    //Create memory copy of .text section of any .dll(s) modified by the cheat

    //Enable syscall hooks, should secure the .text section, protect against overlapping allocations hook NtAllocateVirtualMemory (and allocate anywhere but our allocation), also wipe->relink on process close,
    // and finally ensure usermode cannot detect VAD modifications. Look into reallocations too (?) 
    //initializeHooks();

    //Load DLL, strip/resolve

    //Allocate memory with 'non suspicious' size & flags, size of DLL (page is 4kb)

    
    //Memory now invisible to usermode calls, only accessible via direct access
    //Memory still recorded in PTE, but with flags that do not allow execution
    //Helper::shutdownDriver();
    //kprintf("Driver shut down\n");
    //return STATUS_SUCCESS;

    /*
    

    //Copy DLL into buffer

    //Execute DLL entrypoint
    //DLL allocates a console
    //DLL creates hooks (Ensure VAC cannot / does not read memory 'internally')

    //Driver is finished, and will close once the game is closed


    

    if (false)
    {
        //fumo loader
        //and protect with syscalls

        //call dllentry (try perfectinjector)
        //DLL creates only hooks, and does not create a thread
        //DLL hooks something like CreateMove() and can perform cheat logic in here












        
        //PEPROCESS targProc;
        //UINT64 baseaddy;
        //INT32 buffer;
        //PsLookupProcessByProcessId((HANDLE)procID, &targProc);
        //baseaddy = fetchDLLx64(L"mrmcorer.dll", targProc);
        //Mem::readMem(procID, baseaddy, &buffer, sizeof(buffer));
        //kprintf("Read value: %d\n", buffer);
        
        kprintf("HANDLE: 0x%08X\n", procID);
        SIZE_T dllsize = 0x10;

        PEPROCESS targetEprocess;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)procID, &targetEprocess);
        if (!NT_SUCCESS(status)) {
            kprintf("Failed to get process handle. NTSTATUS: 0x%08X\n", status);
        }

        //Hook ReadMem to prevent reading alloc
        //Alloc
        StealthyAllocateMemory(procID, &allocatedMemory, dllsize);
        //Modify VAD & PTE
        //Execute

    }

    //We are finished, now ensure all anti-cheat / targets are closed
    //checkforprocess();

    //IfhRelease2();
    // 
    //Finished
    if (Helper::Config::targettingKernel) //We can't exit the thread :(
    {
        while (1)
        {
            Helper::SleepInMilliseconds(100);
        }
    }
    else //We can exit! :)
    {
        Helper::shutdownDriver();
        kprintf("Driver shut down\n");
        return STATUS_SUCCESS;
    }
    */
}

void UnloadDriver(PDRIVER_OBJECT pDriverObject) //
{
    UNREFERENCED_PARAMETER(pDriverObject);
    //IoDeleteDevice(pDriverObject->DeviceObject); //KDMAPPER
}

void CreateThread()
{
    PsCreateSystemThread(&Helper::internalData::threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)init, NULL);
}

extern "C"
{
    NTSTATUS DriverEntry() //Must remove args for KDMAPPER release //PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath
    {
        //UNREFERENCED_PARAMETER(RegistryPath);
        //DriverObject->DriverUnload = UnloadDriver;
        CreateThread();
        return STATUS_SUCCESS;
    }
}