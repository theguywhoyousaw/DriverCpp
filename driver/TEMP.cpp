#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>  // for __readmsr
#include <windef.h>
#include <ntimage.h>
#include <ntdef.h>
#include <stdarg.h> // For handling variadic arguments

#pragma once
#pragma warning (disable : 4189)
#pragma warning (disable : 4996)
#pragma warning (disable : 4100)

namespace win22H2
{
#include "22H2.h"
}
#include "hook.hpp"


#define DebugMessage(x, ...) DbgPrintEx(0, 0, x, __VA_ARGS__)
#define DebugMessageAddress(...) DbgPrintEx(0, 0, "%p\n", __VA_ARGS__)
//#define kprintf(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#define combine( ptr, val ) ( (UINT64)ptr + (UINT64)val )
#define IA32_LSTAR 0xC0000082  // MSR for 64-bit system call entry
#define int32_t int
#define uint8_t unsigned char
#define uintptr_t unsigned long long

namespace config
{
    bool targettingKernel = false;
    bool canOutput = true;
}

void kprintf(const char* format, ...) {
    if (!config::canOutput)
        return;
    va_list args;
    va_start(args, format);  // Initialize the va_list to retrieve arguments

    // Forward the arguments to DbgPrintEx with a fixed DPFLTR level
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, args);

    va_end(args);  // Clean up the va_list
}


bool hookinf();
LONG callback(CONTEXT* ContextRecord, EXCEPTION_RECORD* ExceptionRecord)
{
    (void)ContextRecord;
    (void)ExceptionRecord;
    return 1;
}
//0x430 bytes (sizeof)



namespace internalData
{
    HANDLE threadHandle = NULL;
    PEPROCESS eProcessEntry;
    _HANDLE_TABLE_ENTRY* phandleTableEntry;

    _KTHREAD* ktCpy;
    _ETHREAD* etCpy;

    void* initialStack;
    void* kernelStack;
    unsigned long apcQueueable;
    void* stackBase;
    void* stackLimit;
    unsigned long systemThread;
    void* startAddress;
    void* uniqueProcess;
    void* uniqueThread;
    void* win32startAddress;

    void* storage[50];

    _LIST_ENTRY storagel;
    LONG storagell;
    ULONG storage_ulong;
    ULONG storage_ulong_2;
    ULONG storage_ulong_3;
    ULONG storage_ulong_4;
    UCHAR storage_uchar;
    LONG storage_long;

    void saveData(_KTHREAD* kt, _ETHREAD* et)
    {
        /*ktCpy->InitialStack = kt->InitialStack;
        ktCpy->KernelStack = kt->KernelStack;
        ktCpy->ApcQueueable = kt->ApcQueueable;
        ktCpy->StackBase = kt->StackBase;
        ktCpy->StackLimit = kt->StackLimit;
        ktCpy->SystemThread = kt->SystemThread;

        etCpy->StartAddress = et->StartAddress;
        etCpy->Cid.UniqueProcess = et->Cid.UniqueProcess;
        etCpy->Cid.UniqueThread = et->Cid.UniqueThread;
        etCpy->Win32StartAddress = et->Win32StartAddress;
        ktCpy->UserStackWalkActive = kt->UserStackWalkActive;*/

        storage_ulong_4 = kt->UserStackWalkActive;
        storage[0] = kt->KernelStack;
        storage[1] = kt->StackBase;
        storage[2] = kt->StackLimit;
        storage_ulong = kt->SystemThread;
        storage[4] = kt->Win32Thread;
        storage_long = kt->MiscFlags;
        storage_ulong_2 = kt->ApcQueueable;
        storage_ulong_3 = kt->Alertable;
        storage_uchar = kt->Header.Type;

        storage[9] = et->StartAddress;
        storage[10] = et->Cid.UniqueProcess;
        storage[11] = et->Cid.UniqueThread;
        storage[12] = et->Win32StartAddress;
        storagell = et->ExitStatus;
        storagel = et->ThreadListEntry;
    }
    void wipeData(_KTHREAD* kt, _ETHREAD* et)
    {
        LIST_ENTRY x; //For ThreadListEntry
        x.Flink = NULL, x.Blink = NULL;

        kt->UserStackWalkActive = 0x1;
        kt->KernelStack = 0x0;
        kt->StackBase = 0x0;
        kt->StackLimit = 0x0;
        kt->SystemThread = 0x0;
        kt->Win32Thread = 0x0;
        kt->MiscFlags &= 0xffffbfff;
        kt->ApcQueueable = 0x0;
        kt->Alertable = 0x0;
        kt->Header.Type = 22;

        et->StartAddress = (PVOID)0x01;
        et->Cid.UniqueProcess = 0x0;
        et->Cid.UniqueThread = 0x0;
        et->Win32StartAddress = 0x0;
        et->ExitStatus = 0x1;
        et->ThreadListEntry = x;

    }
    void restoreData(_KTHREAD* kt, _ETHREAD* et)
    {
        kt->UserStackWalkActive = storage_ulong_4;
        kt->KernelStack = storage[0];
        kt->StackBase = storage[1];
        kt->StackLimit = storage[2];
        kt->SystemThread = storage_ulong;
        kt->Win32Thread = storage[4];
        kt->MiscFlags = storage_long;
        kt->ApcQueueable = storage_ulong_2;
        kt->Alertable = storage_ulong_3;
        kt->Header.Type = storage_uchar;

        et->StartAddress = storage[9];
        et->Cid.UniqueProcess = storage[10];
        et->Cid.UniqueThread = storage[11];
        et->Win32StartAddress = storage[12];
        et->ExitStatus = storagell;
        et->ThreadListEntry = storagel;
    }
}


NTSTATUS removeThreadEproc(HANDLE thread_id_to_remove, PEPROCESS eProcessEntryPoint)
{
    PETHREAD current_thread = NULL;
    HANDLE current_thread_id = thread_id_to_remove;

    if (NT_SUCCESS(PsLookupThreadByThreadId(current_thread_id, &current_thread)))
    {
        LIST_ENTRY* thread_list_head;
        thread_list_head = (LIST_ENTRY*)combine(eProcessEntryPoint, 0x5e0 /*EPROCESS::ThreadListHead*/);
        PLIST_ENTRY list = thread_list_head;
        while ((list = list->Flink) != thread_list_head)
        {
            _ETHREAD* p_entry;
            p_entry = CONTAINING_RECORD(list, _ETHREAD, ThreadListEntry);
            UINT64 current_tid = (UINT64)PsGetThreadId((PETHREAD)p_entry);
            if (current_tid == (UINT64)current_thread_id)
            {
                _ETHREAD* p_previous_entry = CONTAINING_RECORD(list->Blink, _ETHREAD, ThreadListEntry);
                _ETHREAD* p_next_entry = CONTAINING_RECORD(list->Flink, _ETHREAD, ThreadListEntry);

                p_previous_entry->ThreadListEntry.Flink = list->Flink;
                p_next_entry->ThreadListEntry.Blink = list->Blink;
                return STATUS_SUCCESS;
            }
        }
    }
    return STATUS_ABANDONED;
}


UINT64 siggyScan(ULONG64 offset_plus, ULONG64 offset_neg, int scanSize, int kms)
{
    UNICODE_STRING szPsLookUpName;
    PVOID pPsLookup = 0;
    SIZE_T i = 0;

    RtlInitUnicodeString(&szPsLookUpName, L"PsLookupProcessByProcessId"); //140635A80 
    pPsLookup = MmGetSystemRoutineAddress(&szPsLookUpName);
    if (!pPsLookup)
    {
        kprintf("ppslookup fail");
        return 0;
    }
    if (kms == 1)
    {
        for (i = 0; i < scanSize; i++) //Should find at 'd3'
        {
            ULONG64 addr = (ULONG64)pPsLookup + (ULONG64)i + offset_plus - offset_neg;
            unsigned char addressByte = ((unsigned char*)((PVOID)(addr + 0)))[0];
            unsigned char addressByte2 = ((unsigned char*)((PVOID)(addr + 1)))[0];
            unsigned char addressByte3 = ((unsigned char*)((PVOID)(addr + 2)))[0];
            unsigned char addressByte8 = ((unsigned char*)((PVOID)(addr + 7)))[0];
            unsigned char addressByte9 = ((unsigned char*)((PVOID)(addr + 8)))[0];
            unsigned char addressByte10 = ((unsigned char*)((PVOID)(addr + 9)))[0];

            if (addressByte == 0x48 && addressByte2 == 0x8B && addressByte3 == 0x05 && addressByte8 == 0x0F && addressByte9 == 0xB6 && addressByte10 == 0xEA)
            {
                ULONG32 FoundRelativeOffset = *(ULONG32*)(addr + 3);
                ULONG64 FinalAddress = (ULONG64)(addr + FoundRelativeOffset + 7);

                return FinalAddress;
            }
        }
    }
    else if (kms == 2)
    {
        for (i = 0; i < scanSize; i++) //Should find at 'd3'
        {
            //E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 8B 18 06 00 00
            ULONG64 addr = (ULONG64)pPsLookup + (ULONG64)i + offset_plus - offset_neg;
            unsigned char addressByte = ((unsigned char*)((PVOID)(addr + 0)))[0];
            unsigned char addressByte6 = ((unsigned char*)((PVOID)(addr + 5)))[0];
            unsigned char addressByte11 = ((unsigned char*)((PVOID)(addr + 10)))[0];
            unsigned char addressByte12 = ((unsigned char*)((PVOID)(addr + 11)))[0];
            unsigned char addressByte13 = ((unsigned char*)((PVOID)(addr + 12)))[0];
            unsigned char addressByte14 = ((unsigned char*)((PVOID)(addr + 13)))[0];
            unsigned char addressByte15 = ((unsigned char*)((PVOID)(addr + 14)))[0];
            unsigned char addressByte16 = ((unsigned char*)((PVOID)(addr + 15)))[0];
            unsigned char addressByte17 = ((unsigned char*)((PVOID)(addr + 16)))[0];

            if (addressByte == 0xE8 && addressByte6 == 0xE8 && addressByte11 == 0x48 && addressByte12 == 0x8B && addressByte13 == 0x8B && addressByte14 == 0x18 && addressByte15 == 0x06 && addressByte16 == 0x00 && addressByte17 == 0x00)
            {
                ULONG32 FoundRelativeOffset = *(ULONG32*)(addr + 0x1);
                ULONG64 FinalAddress = (ULONG64)(addr + FoundRelativeOffset + 0x4);

                return FinalAddress;
            }
        }
    }
    return 0;
}

_HANDLE_TABLE_ENTRY* ExpLookupHandleTableEntry(ULONG64* pHandleTable, ULONG64 Handle)
{
    ULONG64 tableLevel = Handle & -4;

    if (tableLevel >= *pHandleTable)
        return 0;

    ULONG64 tableBase = *(pHandleTable + 1);
    ULONG64 tableIndex = (tableBase & 3);

    switch (tableIndex)
    {
    case 0:
    {
        return (_HANDLE_TABLE_ENTRY*)(tableBase + 4 * tableLevel);
    }
    case 1:
    {
        return (_HANDLE_TABLE_ENTRY*)(*(ULONG_PTR*)(tableBase + 8 * (tableLevel >> 10) - 1) + 4 * (tableLevel & 0x3FF));
    }
    case 2:
    {
        return (_HANDLE_TABLE_ENTRY*)(*(ULONG_PTR*)(*(ULONG_PTR*)(tableBase + 8 * (tableLevel >> 19) - 2) + 8 * ((tableLevel >> 10) & 0x1FF)) + 4 * (tableLevel & 0x3FF));
    }
    default:
        return 0;
    }
}

typedef BOOLEAN(*func)(const _HANDLE_TABLE*, const HANDLE, const _HANDLE_TABLE_ENTRY*);
func ExDestroyHandle;

NTSTATUS UnlinkPSPCid()
{
    //ULONG64* pHandleTable = *(ULONG64**)siggyScan(0x100, 0x0, 0x100, 1);
    //ULONG64* PexDestroyHandle = *(ULONG64**)siggyScan(0x0, 0x358738, 0x10000, 2);
    ULONG64* pPspCidTable = (ULONG64*)siggyScan(0x100, 0x0, 0x100, 1);
    ULONG64* pEXDestroyHandle = (ULONG64*)siggyScan(0x0, 0x358738, 0x10000, 2);
    if (pPspCidTable == 0 || pEXDestroyHandle == 0)
    {
        return STATUS_ABANDONED;
    }
    UINT64* pHandleTable = (UINT64*)*pPspCidTable;

    _HANDLE_TABLE_ENTRY* pCidEntry = ExpLookupHandleTableEntry(pHandleTable, (ULONG64)(PsGetCurrentThreadId()));

    if (pCidEntry == NULL)
    {
        return STATUS_ABANDONED;
    }

    //kprintf(0, 0, "Handle table: %p", pHandleTable);
    //kprintf(0, 0, "Cid entry: %p", pCidEntry);
    //kprintf(0, 0, "ObjectPointerBits: %p", pCidEntry->ObjectPointerBits);

    ExDestroyHandle = reinterpret_cast<func>(pEXDestroyHandle);
    ExDestroyHandle(reinterpret_cast<_HANDLE_TABLE*>(pHandleTable), (PsGetCurrentThreadId()), pCidEntry);

    if (pCidEntry->ObjectPointerBits == 0)
    {
        //kprintf(0, 0, "Entry should be removed removed");
        //kprintf(0, 0, "ObjectPointerBits now: %p", pCidEntry->ObjectPointerBits);
    }
    else
    {
        kprintf("opb failed\n");
        return STATUS_ABANDONED;
    }

    //kt = (_KTHREAD*)((pCidEntry->ObjectPointerBits << 4) | 0xffff000000000000); //KTHREAD

    return STATUS_SUCCESS;
}

void SleepInMilliseconds(LONG milliseconds) {
    LARGE_INTEGER interval;
    // Convert milliseconds to 100-nanosecond intervals and make it negative
    interval.QuadPart = -(10 * 1000 * milliseconds);  // 1000 * 10 for 100ns intervals

    // Call KeDelayExecutionThread to sleep the current thread
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}


void* holder = NULL;


bool shutdownDriver()
{
    //NTSTATUS callret;
    _KTHREAD* kCurrentThread = (_KTHREAD*)holder;
    _ETHREAD* eCurrentThread = (_ETHREAD*)holder;
    internalData::restoreData(kCurrentThread, eCurrentThread);
    return true;
}


bool setupDriver()
{
    NTSTATUS callret; //Generic response info

    holder = PsGetCurrentThread();
    _KTHREAD* kCurrentThread = (_KTHREAD*)holder;
    _ETHREAD* eCurrentThread = (_ETHREAD*)holder;

    //Remove thread from eProcess list 
    for (int i = 1; i < 5000; i++)
    {
        callret = PsLookupProcessByProcessId((HANDLE)i, &internalData::eProcessEntry); //Find any entry to the eprocess chain
        if (callret == STATUS_SUCCESS)
            break;
    }
    if (callret != STATUS_SUCCESS)
    {
        kprintf("Failed to locate link chain\n");
        return 0;
    }

    HANDLE threadID = PsGetCurrentThreadId();
    callret = removeThreadEproc(threadID, internalData::eProcessEntry);
    if (callret != STATUS_SUCCESS) { kprintf("Failed unlink\n"); return 0; }

    if (config::targettingKernel)
    {
        callret = UnlinkPSPCid();
        if (callret != STATUS_SUCCESS) { kprintf("Failed pspcid\n"); return 0; }
    }

    kprintf("Everything looks good, 'going dark' \n");

    internalData::saveData(kCurrentThread, eCurrentThread);
    //DebugMessageAddress(kCurrentThread->StackBase);
    //DebugMessageAddress(eCurrentThread->StartAddress);
    internalData::wipeData(kCurrentThread, eCurrentThread);
    //DebugMessageAddress(kCurrentThread->StackBase);
    //DebugMessageAddress(eCurrentThread->StartAddress);
    //internalData::restoreData(kCurrentThread, eCurrentThread);
    //DebugMessageAddress(kCurrentThread->StackBase);
    //DebugMessageAddress(eCurrentThread->StartAddress);

    return true;
}



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




static wchar_t IfhMagicFileName[] = L"ifh--";
static UNICODE_STRING StringNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
static NtCreateFile_t OriginalNtCreateFile = NULL;
static UNICODE_STRING StringNtReadVirtualMemory = RTL_CONSTANT_STRING(L"NtReadVirtualMemory");
static UNICODE_STRING StringZwReadVirtualMemory = RTL_CONSTANT_STRING(L"ZwReadVirtualMemory");
static NtReadVirtualMemory_t OriginalNtReadVirtualMemory = NULL;
bool ft = true;

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


    UNREFERENCED_PARAMETER(SystemCallIndex);

    //
    // In our demo, we care only about nt!NtCreateFile calls.
    //
    if (*SystemCallFunction == OriginalNtCreateFile)
    {
        *SystemCallFunction = DetourNtCreateFile;
    }

    if (SystemCallIndex == 0x003f)
    {
        OriginalNtReadVirtualMemory = (NtReadVirtualMemory_t)*SystemCallFunction;
        *SystemCallFunction = DetourNtReadVirtualMemory;
    }
}


bool initializeHooks()
{
    OriginalNtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&StringNtCreateFile);
    OriginalNtReadVirtualMemory = (NtReadVirtualMemory_t)MmGetSystemRoutineAddress(&StringNtReadVirtualMemory);
    if (!OriginalNtCreateFile)
    {
        DebugMessage("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtCreateFile);
        return 0;
    }

    bool stat = IfhInitialize2(SyscallStub);
    if (stat == false)
    {
        DebugMessage("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", stat);
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

#define SystemModuleInformation 11  // For NtQuerySystemInformation

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

} SST, * pSST;

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
        UINT32 routineOffset = (UINT32) * (UINT64*)(KiServiceTable + (4 * 0x0055)); //0x003f
        kprintf("Pattern found at address: %p\n", routineOffset);
        //routineOffset = 4 bytes

        //RoutineAddress = KiServiceTable + (routineOffset >>> 4)
        UINT64 RoutineAddress = KiServiceTable + (routineOffset >> 4);
        kprintf("Pattern found at address: %p\n", RoutineAddress);
        kprintf("Pattern found at address: %p\n", MmGetSystemRoutineAddress(&StringNtCreateFile));
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
    kprintf("Pattern found at address: %p\n", result);
    return true;
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

    DebugMessage("[++] Loaded\n");
    RTL_OSVERSIONINFOW ver = { 0 };
    ver.dwOSVersionInfoSize = sizeof(ver);
    RtlGetVersion(&ver);

    if (ver.dwBuildNumber == 19045)
    {
        kprintf("22h2!");
    }
    else
    {
        kprintf("something else");
    }


    BOOL result;

    //Target game
    //namespace.target("cs2.exe", true, true)

    //Hide thread
    result = setupDriver();
    if (!result)
        return STATUS_ABANDONED;

    //Locate syscalls
    result = locateSyscalls();
    if (!result)
        return STATUS_ABANDONED;

    //Hook important syscalls
    //initializeHooks();

    //Wait for target process
    //waitforprocess();

    //Inject DLL via physmem
    //inject(); //<- handles protection before injection


    //We are finished, now ensure all anti-cheat / targets are closed
    //checkforprocess();

    //IfhRelease2();
    // 
    //Finished
    if (config::targettingKernel) //We can't exit the thread :(
    {
        while (1)
        {
            SleepInMilliseconds(100);
        }
    }
    else //We can exit! :)
    {
        shutdownDriver();
        kprintf("Driver shut down");
        return STATUS_SUCCESS;
    }

}

void UnloadDriver(PDRIVER_OBJECT pDriverObject) //
{
    UNREFERENCED_PARAMETER(pDriverObject);
    //IoDeleteDevice(pDriverObject->DeviceObject); //KDMAPPER
}

void CreateThread()
{
    PsCreateSystemThread(&internalData::threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)init, NULL);
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



/*if (base)
{
    long id = *(long*)(base + 0x440); //UniqueProcessId_o
    UINT64 baseaddy = base + 0x520; //SectionBaseAddress
    PEPROCESS targProc;
    PsLookupProcessByProcessId((HANDLE)id, &targProc);
    baseaddy = fetchDLLx64(L"mrmcorer.dll", targProc);
    if (!baseaddy)
    {
        kprintf("baseaddy incr");
        Helper::shutdownDriver();
        return STATUS_ABANDONED;
    }
    INT32 buffer;
    //BaseAddr = fetchDLLx64(L"UnityPlayer.dll", targProc);
    kprintf("Attempting read..\n");
    Mem::readMem(id, baseaddy, &buffer, sizeof(buffer));
    kprintf("Base found at: %p\n", baseaddy);
    kprintf("Successfully read value: %d\n", buffer);

    NTSTATUS status = ReadProcessMemory32(targProc, (PVOID)baseaddy, &buffer);
    if (NT_SUCCESS(status)) {
        kprintf("Successfully read value: %d\n", buffer);
    }
    else {
        kprintf("Failed to read memory: 0x%X\n", status);
    }
}*/