#include "sys_ops.h"
#include "Mem.h"
#include "Helper.h"

namespace sys
{
    NTSTATUS StealthAlloc(PEPROCESS target, PVOID* MappedAddress, SIZE_T allocationSize)
    {
        HANDLE processHandle;
        // Step 2: Open the process object
        if (!NT_SUCCESS(ObOpenObjectByPointer(target, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &processHandle)))
        {
            kprintf("ObOpenObjectByPointer failed\n");
            return STATUS_UNSUCCESSFUL;
        }
        HANDLE sectionHandle = NULL;
        LARGE_INTEGER sectionSize;
        SIZE_T viewSize = 0;

        // Initialize the section size
        sectionSize.QuadPart = allocationSize;
        if (!NT_SUCCESS(ZwCreateSection(
            &sectionHandle,
            SECTION_ALL_ACCESS,
            NULL,           // Object attributes
            &sectionSize,   // Size of the section
            PAGE_READWRITE, // Memory protection
            SEC_COMMIT,     // Commit memory immediately
            NULL            // No file handle (anonymous memory)
        ))) {
            kprintf("ZwCreateSection failed.\n");
            return STATUS_UNSUCCESSFUL;
        }

        if (!NT_SUCCESS(ZwMapViewOfSection(
            sectionHandle,
            processHandle, // Map into the target process
            MappedAddress,     // Output: address in user mode
            0L,                  // Zero bits
            allocationSize,          // Committed size
            NULL,                // No offset
            &viewSize,           // View size (input/output)
            ViewUnmap,           // Unmap when handle is closed
            MEM_TOP_DOWN,                  // Allocation type
            PAGE_READWRITE       // Protection
        ))) {
            kprintf("ZwMapViewOfSection failed.\n");
            return STATUS_UNSUCCESSFUL;
        }

        //Unlink from the VAD

        //Modify & spoof PTE

        KAPC_STATE apcState;
        SIZE_T pageSize = PAGE_SIZE;
        KeStackAttachProcess(target, &apcState);

        __try {
            // Step 2: Access (touch) each page in the user-mode mapped memory
            for (SIZE_T offset = 0; offset < allocationSize; offset += pageSize) {
                // Safely touch the page by reading or writing
                *(volatile PBYTE)((UINT64)*MappedAddress + offset) = 0;  // Write to each page to force it into physical memory
            }

            kprintf("[+] Successfully touched user-mode pages from kernel.\n");
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            kprintf("[-] Exception while touching user-mode pages: 0x%x\n", GetExceptionCode());
            // Handle access violation or page faults
            KeUnstackDetachProcess(&apcState);
            return STATUS_UNSUCCESSFUL;
        }

        /*PVOID testMemoryBuffer = ExAllocatePoolWithTag(NonPagedPool, allocationSize, 'To3l');

        if (!Mem::readMem(target, *MappedAddress, testMemoryBuffer, allocationSize))
        {
            ExFreePoolWithTag(testMemoryBuffer, 'To3l');
            KeUnstackDetachProcess(&apcState);
            return STATUS_UNSUCCESSFUL;
        }
        if (!Mem::writeMem(target, *MappedAddress, testMemoryBuffer, allocationSize))
        {
            ExFreePoolWithTag(testMemoryBuffer, 'To3l');
            KeUnstackDetachProcess(&apcState);
            return STATUS_UNSUCCESSFUL;
        }

        ExFreePoolWithTag(testMemoryBuffer, 'To3l');*/

        // Step 3: Detach from the process's address space
        KeUnstackDetachProcess(&apcState);

        return STATUS_SUCCESS;
        // Step 3: Allocate virtual memory in the target process

        /*kprintf("Success\n");
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
        }*/
    }

    typedef struct _SECTION_MAP_INFO {
        PVOID SectionBaseAddress;  // Actual base address where the section was allocated
        ULONG VirtualAddress;      // Virtual address from the section header (RVA)
        ULONG Size;                // Size of the section
    } SECTION_MAP_INFO;

    
    typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR  FullPathName[256];
    } SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

    typedef struct _SYSTEM_MODULE_INFORMATION {
        ULONG ModulesCount;
        SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
    } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

    extern "C" {
        NTSTATUS ZwQuerySystemInformation(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );
    }
#define SystemModuleInformation 11



    NTSTATUS GetKernelModuleBaseByName(const char* moduleName, PVOID* moduleBase, ULONG* moduleSize) {
        ULONG bytes = 0;
        NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bytes);

        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            return status;
        }

        // Allocate memory to store module information
        PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, bytes, 'modl');
        if (!pModuleInfo) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Fetch the system's module information
        status = ZwQuerySystemInformation(SystemModuleInformation, pModuleInfo, bytes, &bytes);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(pModuleInfo, 'modl');
            return status;
        }

        // Iterate through all loaded modules and compare names
        for (ULONG i = 0; i < pModuleInfo->ModulesCount; i++) {
            PSYSTEM_MODULE_INFORMATION_ENTRY pEntry = &pModuleInfo->Modules[i];

            // Use FullPathName + OffsetToFileName to get the module's file name
            const char* fileName = (const char*)(pEntry->FullPathName + pEntry->OffsetToFileName);

            // Compare the module name with the one we are looking for (case-insensitive)
            if (_stricmp(fileName, moduleName) == 0) {
                *moduleBase = pEntry->ImageBase;  // Return the base address of the found module
                *moduleSize = pEntry->ImageSize;
                ExFreePoolWithTag(pModuleInfo, 'modl');
                return STATUS_SUCCESS;
            }
        }

        ExFreePoolWithTag(pModuleInfo, 'modl');
        return STATUS_NOT_FOUND;  // Module was not found
    }

    ULONG SectionToProtectionFlags(ULONG Characteristics)
    {
        if (Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            if (Characteristics & IMAGE_SCN_MEM_WRITE)
                return PAGE_EXECUTE_READWRITE;
            else if (Characteristics & IMAGE_SCN_MEM_READ)
                return PAGE_EXECUTE_READ;
            else
                return PAGE_EXECUTE;
        }
        else
        {
            if (Characteristics & IMAGE_SCN_MEM_WRITE)
                return PAGE_READWRITE;
            else if (Characteristics & IMAGE_SCN_MEM_READ)
                return PAGE_READONLY;
            else
                return PAGE_NOACCESS;
        }
    }

    PVOID RvaToVa(ULONG Rva, PVOID Base)
    {
        return (PVOID)((PUCHAR)Base + Rva);
    }

    SIZE_T CalculateTotalImageSize(PVOID dllBuffer)
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)dllBuffer + dosHeader->e_lfanew);

        // Start with the size of the headers.
        SIZE_T totalSize = ntHeaders->OptionalHeader.SizeOfHeaders;

        PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(ntHeaders);

        // Iterate through each section to calculate total memory size.
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, Section++)
        {
            // Determine the size required for this section in memory, including alignment.
            SIZE_T sectionEnd = Section->VirtualAddress + Section->Misc.VirtualSize;

            // Align section size to the SectionAlignment.
            sectionEnd = (sectionEnd + ntHeaders->OptionalHeader.SectionAlignment - 1) & ~((SIZE_T)ntHeaders->OptionalHeader.SectionAlignment - 1);

            // Update total size if this section extends beyond the current total size.
            if (sectionEnd > totalSize)
            {
                totalSize = sectionEnd;
            }
        }

        return totalSize;
    }

    NTSTATUS CopySections(PEPROCESS target, PVOID allocationAddress, PVOID dllBuffer)
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)dllBuffer + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)((PUCHAR)ntHeaders + sizeof(IMAGE_NT_HEADERS));

        PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, Section++) {
            PVOID UserSectionBase = NULL;
            SIZE_T SectionVirtualSize = Section->Misc.VirtualSize;
            SIZE_T SectionRawSize = Section->SizeOfRawData;

            ULONG ProtectionFlags = SectionToProtectionFlags(Section->Characteristics);

            // Align the section size properly.
            SectionVirtualSize = (SectionVirtualSize + ntHeaders->OptionalHeader.SectionAlignment - 1) & ~((SIZE_T)ntHeaders->OptionalHeader.SectionAlignment - 1);

            if (SectionRawSize > 0)
            {
                SIZE_T CopySize = min(SectionRawSize, SectionVirtualSize);
                if (!Mem::writeMem(target, allocationAddress, RvaToVa(Section->PointerToRawData, dllBuffer), CopySize))
                {
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }

        return STATUS_SUCCESS;
    }
    PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(UINT64 rva, PIMAGE_NT_HEADERS ntHeaders)
    {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (unsigned i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
        {
            UINT64 size = section->Misc.VirtualSize;
            if (rva >= section->VirtualAddress && rva < section->VirtualAddress + size)
                return section;
        }
        return NULL;
    }

    PVOID GetPtrFromRVA(UINT64 rva, PIMAGE_NT_HEADERS ntHeaders, PVOID baseAddress)
    {
        PIMAGE_SECTION_HEADER section = GetEnclosingSectionHeader(rva, ntHeaders);
        if (!section)
            return NULL;

        UINT64 delta = (UINT64)(section->VirtualAddress - section->PointerToRawData);
        return (PVOID)((PUCHAR)baseAddress + rva - delta);
    }

    typedef struct _API_SET_NAMESPACE {
        ULONG Version;
        ULONG Size;
        ULONG Flags;
        ULONG Count;
        ULONG EntryOffset;
        ULONG HashOffset;
        ULONG HashFactor;
    } API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

    typedef struct _API_SET_NAMESPACE_ENTRY {
        ULONG Flags;
        ULONG NameOffset;
        ULONG NameLength;
        ULONG HashedLength;
        ULONG ValueOffset;
        ULONG ValueCount;
    } API_SET_NAMESPACE_ENTRY, * PAPI_SET_NAMESPACE_ENTRY;

    typedef struct _API_SET_VALUE_ENTRY {
        ULONG Flags;
        ULONG NameOffset;
        ULONG NameLength;
        ULONG ValueOffset;
        ULONG ValueLength;
    } API_SET_VALUE_ENTRY, * PAPI_SET_VALUE_ENTRY;

    // Function to convert a UNICODE string
    void UnicodeFromAscii(UNICODE_STRING* destination, const char* source)
    {
        ANSI_STRING ansiString;
        RtlInitAnsiString(&ansiString, source);
        RtlAnsiStringToUnicodeString(destination, &ansiString, TRUE);
    }


    PVOID GetApiSetMapFromPeb(PEPROCESS target)
    {
        // Get the PEB from the process
        PVOID pebPtr = (PVOID)((UINT64)target + 0x550);
        PVOID pebAddr = *(PVOID*)pebPtr;
        PVOID pebLoc = NULL;
        //kprintf("pebPtr: %p", pebPtr);
        //kprintf("pebAddr: %p", pebAddr);

        PVOID UMAddress = NULL;

        PVOID apiSetMapPtr = ((PUCHAR)pebAddr) + 0x68;
        API_SET_NAMESPACE apiset = { 0 };
        if (!Mem::readMem(target, apiSetMapPtr, &UMAddress, sizeof(PVOID)))
        {
            return { 0 };
        }
        //kprintf("apiSetMapAddr: %p", UMAddress);
        return UMAddress;
    }

    // Resolving API set to actual DLL in kernel mode
    NTSTATUS ResolveApiSetDllName(API_SET_NAMESPACE apiSetNamespace, PUNICODE_STRING apiSetName, PUNICODE_STRING resolvedDllName, PEPROCESS target, PVOID apiSetNamespaceUMAddress) {
        if (apiSetNamespace.Size == 0x0 || !apiSetName || !resolvedDllName) {
            kprintf("Invalid parameters provided to ResolveApiSetDllName.\n");
            return STATUS_INVALID_PARAMETER;
        }
        
        PVOID currentEntryAddress = (PVOID)((UINT64)apiSetNamespaceUMAddress + apiSetNamespace.EntryOffset);
        for (ULONG i = 0; i < apiSetNamespace.Count; i++)
        {
            API_SET_NAMESPACE_ENTRY entry;
            kprintf("currentEntryAddr: %p", currentEntryAddress);
            kprintf("currentEntryOffset: %p", apiSetNamespace.EntryOffset);
            if (apiSetNamespace.Size != 0x0)
                return STATUS_ABANDONED;
            if (!Mem::CopyUsermodeStructureToKernel(target, currentEntryAddress, sizeof(API_SET_NAMESPACE_ENTRY), &entry))
            {
                kprintf("Fatal!");
                return STATUS_ABANDONED;
            }

            PVOID nameAddress = (PVOID)((UINT64)apiSetNamespaceUMAddress + entry.NameOffset);
            WCHAR entryName[256] = { 0 };
            if (entry.NameLength >= sizeof(entryName) || entry.NameLength % sizeof(WCHAR) != 0) {
                kprintf("Invalid entry name length: %lu\n", entry.NameLength);
                return STATUS_INVALID_PARAMETER;
            }

            if (!Mem::CopyUsermodeStructureToKernel(target, nameAddress, entry.NameLength, entryName))
            {
                kprintf("Fatal! Failed to copy entry name.\n");
                return STATUS_ABANDONED;
            }

            UNICODE_STRING entryNameString;
            RtlInitUnicodeString(&entryNameString, entryName);


            if (RtlEqualUnicodeString(apiSetName, &entryNameString, TRUE))
            {
                kprintf("Match found for API Set DLL!\n");
                // Continue processing...
            }
            else
            {
                kprintf("No match");
            }

            currentEntryAddress = (PVOID)((UINT64)currentEntryAddress + sizeof(API_SET_NAMESPACE_ENTRY));
        }
        return STATUS_SUCCESS;
    }

    void TrimDllExtension(PCHAR dllName)
    {
        // Check if the dllName ends with ".dll" (case insensitive)
        size_t len = strlen(dllName);
        if (len >= 4 && _stricmp(dllName + len - 4, ".dll") == 0)
        {
            // Null-terminate the string before ".dll"
            dllName[len - 4] = '\0';
        }
    }
    void ANSIToUnicode(const char* ansiStr, WCHAR* unicodeStr, size_t unicodeStrSize)
    {
        // Check for null pointers
        if (ansiStr == NULL || unicodeStr == NULL || unicodeStrSize == 0)
            return;

        // Get the length of the ANSI string
        size_t len = strlen(ansiStr);

        // Ensure we don't exceed the buffer size
        if (len >= unicodeStrSize)
            len = unicodeStrSize - 1;  // Leave space for null terminator

        // Perform the conversion (simple copy with type casting)
        for (size_t i = 0; i < len; ++i)
        {
            unicodeStr[i] = (WCHAR)ansiStr[i];  // Cast each char to WCHAR
        }

        // Null-terminate the wide-character string
        unicodeStr[len] = L'\0';
    }

    NTSTATUS ResolveImportsTidy(PEPROCESS target, PVOID allocationAddress, PVOID dllBuffer, PVOID ntoskrnlBase)
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)dllBuffer + dosHeader->e_lfanew);
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)GetPtrFromRVA(
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
            ntHeaders,
            dllBuffer
        );
        // Validate if there's an import directory entry
        if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 || importDescriptor == NULL)
        {
            kprintf("This DLL has no imports to resolve\n");
            return STATUS_SUCCESS;
        }
        PVOID usermodeAddressOfApisetmap = GetApiSetMapFromPeb(target); //Fetch in advance

        while (importDescriptor->Name)
        {

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)GetPtrFromRVA(
                importDescriptor->OriginalFirstThunk,
                ntHeaders,
                dllBuffer
            );//((PUCHAR)dllBuffer + importDescriptor->OriginalFirstThunk);
            PIMAGE_THUNK_DATA funcAddrArray = (PIMAGE_THUNK_DATA)GetPtrFromRVA(
                importDescriptor->FirstThunk,
                ntHeaders,
                dllBuffer
            );//((PUCHAR)dllBuffer + importDescriptor->FirstThunk);
            while (thunk->u1.AddressOfData != 0) {
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Import by ordinal
                    ULONG ordinal = (ULONG)(thunk->u1.Ordinal & 0xFFFF);
                    kprintf("Imported by Ordinal: %lu\n", ordinal);
                }
                else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)GetPtrFromRVA(
                        thunk->u1.AddressOfData,
                        ntHeaders,
                        dllBuffer
                    );//((PUCHAR)dllBuffer + thunk->u1.AddressOfData);
                    kprintf("Imported function: %s at address: 0x%p\n", importByName->Name, funcAddrArray->u1.Function);
                }
                thunk++;
                funcAddrArray++;
            }

            // Get the name of the imported DLL
            PCHAR dllName = (PCHAR)GetPtrFromRVA(importDescriptor->Name, ntHeaders, dllBuffer);

            // Debugging section for the DLL name
            PIMAGE_SECTION_HEADER nameSection = GetEnclosingSectionHeader(importDescriptor->Name, ntHeaders);
            if (!nameSection)
            {
                kprintf("Name RVA is not within any section! Invalid import descriptor.\n");
                break;
            }

            //kprintf("Section containing Name: %s\n", nameSection->Name);
            //kprintf("DLL Name Address: %p, DLL Name: %s\n", dllName, dllName ? dllName : "NULL");

            // Validate the name string
            if (dllName == NULL || *dllName == '\0')
            {
                kprintf("Invalid DLL name in import descriptor\n");
                break;
            }


            //If can locate file, load
            const CHAR apiSetPrefix[] = "api-ms-";
            const CHAR apiSetPrefixMs[] = "ext-ms-";
            SIZE_T prefixLength = sizeof(apiSetPrefix) - 1; // Length of "api-ms-" without the null terminator
            SIZE_T prefixLengthMs = sizeof(apiSetPrefixMs) - 1; // Length of "ext-ms-" without the null terminator

            // If dll is stored in api set
            if (dllName && ((strncmp(dllName, apiSetPrefix, prefixLength) == 0) || (strncmp(dllName, apiSetPrefixMs, prefixLengthMs) == 0)))
            {
                TrimDllExtension(dllName);
                WCHAR wideDllName[128] = { 0 };
                ANSIToUnicode(dllName, wideDllName, sizeof(wideDllName) / sizeof(WCHAR));


                // Get the API Set Namespace from the target process's PEB
                
                if (usermodeAddressOfApisetmap == NULL)
                {
                    kprintf("Failed to retrieve API Set map address\n");
                    return STATUS_ABANDONED;
                }

                API_SET_NAMESPACE apiset_data;
                if (!Mem::CopyUsermodeStructureToKernel(target, usermodeAddressOfApisetmap, sizeof(API_SET_NAMESPACE), &apiset_data) || apiset_data.Count == 0)
                {
                    kprintf("Failed to retrieve API_SET_NAMESPACE or Count is zero\n");
                    return STATUS_ABANDONED;
                }
                // Ensure we're running at PASSIVE_LEVEL
                if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                {
                    kprintf("Error: Not running at PASSIVE_LEVEL\n");
                    return STATUS_UNSUCCESSFUL;
                }

                // Iterate through each API Set namespace entry
                PVOID currentEntryAddress = (PVOID)((UINT64)usermodeAddressOfApisetmap + apiset_data.EntryOffset);

                for (ULONG i = 0; i < (apiset_data.Count); i++)
                {
                    API_SET_NAMESPACE_ENTRY entry = { 0 };
                    if (!Mem::CopyUsermodeStructureToKernel(target, currentEntryAddress, sizeof(API_SET_NAMESPACE_ENTRY), &entry))
                    {
                        kprintf("Failed to copy API_SET_NAMESPACE_ENTRY\n");
                        return STATUS_ABANDONED;
                    }



                    //kprintf("Entry %lu: NameOffset: %lu, NameLength: %lu, ValueOffset: %lu, ValueCount: %lu\n",
                        //i, entry.NameOffset, entry.NameLength, entry.ValueOffset, entry.ValueCount);
                    
                    


                    // Check if the NameLength is reasonable
                    if (entry.NameLength >= sizeof(WCHAR) * 128)
                    {
                        kprintf("Entry name length exceeds buffer size: %lu\n", entry.NameLength);
                        return STATUS_INVALID_PARAMETER;
                    }
                    PVOID currentEntryNameAddress = (PVOID)((UINT64)usermodeAddressOfApisetmap + entry.NameOffset);
                    WCHAR entryNameBuffer[128] = { 0 };
                    if (!Mem::CopyUsermodeStructureToKernel(target, currentEntryNameAddress, entry.NameLength, entryNameBuffer))
                    {
                        kprintf("Failed to copy entry name\n");
                        return STATUS_ABANDONED;
                    }
                    entryNameBuffer[entry.NameLength / sizeof(WCHAR)] = L'\0'; // Null-terminate the name buffer


                    // Ensure entryNameBuffer is null-terminated correctly
                    entryNameBuffer[entry.NameLength / sizeof(WCHAR)] = L'\0';

                    // Compare the entry name with the DLL name (Unicode)
                    if (_wcsicmp((WCHAR*)wideDllName, entryNameBuffer) == 0)
                    {
                        for (ULONG j = 0; j < entry.ValueCount; j++)
                        {
                            // Calculate the address of the current value entry
                            API_SET_VALUE_ENTRY valueEntry = { 0 };
                            PVOID valueEntryAddress = (PVOID)((UINT64)usermodeAddressOfApisetmap + entry.ValueOffset + j * sizeof(API_SET_VALUE_ENTRY));

                            // Copy the value entry structure
                            if (!Mem::CopyUsermodeStructureToKernel(target, valueEntryAddress, sizeof(API_SET_VALUE_ENTRY), &valueEntry))
                            {
                                kprintf("Failed to copy API_SET_VALUE_ENTRY\n");
                                return STATUS_ABANDONED;
                            }

                            // Read the resolved DLL name from the value entry
                            WCHAR resolvedDllName[MAX_PATH] = { 0 };
                            PVOID resolvedNameAddress = (PVOID)((UINT64)usermodeAddressOfApisetmap + valueEntry.ValueOffset);

                            // Ensure the length of the DLL name doesn't exceed buffer size
                            if (valueEntry.ValueLength >= sizeof(resolvedDllName))
                            {
                                kprintf("Resolved DLL name length exceeds buffer size: %lu\n", valueEntry.ValueLength);
                                return STATUS_INVALID_PARAMETER;
                            }

                            // Copy the resolved DLL name into the buffer
                            if (!Mem::CopyUsermodeStructureToKernel(target, resolvedNameAddress, valueEntry.ValueLength, resolvedDllName))
                            {
                                kprintf("Failed to copy resolved DLL name\n");
                                return STATUS_ABANDONED;
                            }

                            // Null-terminate the resolved DLL name
                            resolvedDllName[valueEntry.ValueLength / sizeof(WCHAR)] = L'\0';


                            kprintf("Resolved DLL %ws\n", resolvedDllName);
                        }
                    }
                    //kprintf("Found API Set Name: %ws\n", entryNameBuffer);

                    currentEntryAddress = (PVOID)((UINT64)currentEntryAddress + sizeof(API_SET_NAMESPACE_ENTRY));

                    // Add a sanity check to ensure we don't exceed the bounds
                    if ((UINT64)currentEntryAddress >= ((UINT64)usermodeAddressOfApisetmap + apiset_data.Size))
                    {
                        kprintf("Exceeded valid memory range for entries\n");
                        return STATUS_UNSUCCESSFUL;
                    }
                }
            }
            else
            {
                kprintf("Resolved DLL %s\n", dllName);
            }

            importDescriptor++;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS ResolveRelocationsTidy(PEPROCESS target, PVOID dllBuffer, UINT64 mappedLocationBase)
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)dllBuffer + dosHeader->e_lfanew);

        IMAGE_DATA_DIRECTORY relocationDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocationDirectory.Size == 0)
        {
            kprintf("Relocation directory was empty?\n");
            return STATUS_SUCCESS;
        }

        IMAGE_BASE_RELOCATION* baseReloc = (IMAGE_BASE_RELOCATION*)(mappedLocationBase + relocationDirectory.VirtualAddress);
        //while (baseReloc->VirtualAddress)



        return STATUS_SUCCESS;
    }

    NTSTATUS setupDll(PEPROCESS target, PVOID dllBuffer, SIZE_T dllSizeRaw, PVOID* returnValue, PVOID ntoskrnl)
    {
        kprintf("dll setup\n");
        PVOID allocationAddr = NULL;
        NTSTATUS status;
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)dllBuffer + dosHeader->e_lfanew);

        //Validate
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return STATUS_UNSUCCESSFUL;

        //Calculate virtual size
        SIZE_T dllSizeVirtual = CalculateTotalImageSize(dllBuffer);

        //Allocate sections
        if(!NT_SUCCESS(StealthAlloc(target, &allocationAddr, dllSizeVirtual)))
            return STATUS_UNSUCCESSFUL;
        kprintf("Allocation successful\n");

        if (!NT_SUCCESS(CopySections(target, allocationAddr, dllBuffer)))
            return STATUS_UNSUCCESSFUL;
        kprintf("Copy sections successful\n");

        if (!NT_SUCCESS(ResolveImportsTidy(target, allocationAddr, dllBuffer, ntoskrnl)))
            return STATUS_UNSUCCESSFUL;
        kprintf("Resolve imports successful\n");

        if (!NT_SUCCESS(ResolveRelocationsTidy(target, dllBuffer, (UINT64)allocationAddr)))
            return STATUS_UNSUCCESSFUL;
        kprintf("Resolve relocations successful\n");
        *returnValue = allocationAddr;

        return STATUS_SUCCESS;
    }


    NTSTATUS N_StealthSetupAndMapDll(PEPROCESS target, PVOID* MappedAddress, PVOID Dll, SIZE_T allocationSize)
    {
        return STATUS_SUCCESS;
        /*
        (void)allocationSize;
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Dll;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)Dll + dosHeader->e_lfanew);
        //ULONGLONG preferredBase = ntHeaders->OptionalHeader.ImageBase;
        ULONG numberOfSections = ntHeaders->FileHeader.NumberOfSections;
        long procID = *(long*)((UINT64)target + 0x440); //Cancer

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return STATUS_UNSUCCESSFUL;
        

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        SECTION_MAP_INFO* sectionMap = (SECTION_MAP_INFO*)ExAllocatePool(NonPagedPool, numberOfSections * sizeof(SECTION_MAP_INFO));

        for (ULONG i = 0; i < numberOfSections; i++, section++)
        {
            kprintf("Section iteration");
            // Allocate memory for each section in the user-mode process.
            //PVOID sectionAddress = (PVOID)((PUCHAR)userBaseAddress + section->VirtualAddress);
            SIZE_T sectionSize = ALIGN_UP(section->Misc.VirtualSize, PAGE_SIZE); // Align to page size.
            PVOID sectionBase = NULL;
            //SIZE_T viewSize = sectionSize;
            if (!NT_SUCCESS(StealthAlloc(target, &sectionBase, sectionSize)))
                return STATUS_UNSUCCESSFUL;
            PVOID sectionSource = (PVOID)((PUCHAR)Dll + section->PointerToRawData);
            if (!NT_SUCCESS(Mem::writeMem(procID, sectionBase, sectionSource, sectionSize)))
                return STATUS_UNSUCCESSFUL;
            sectionMap[i].SectionBaseAddress = sectionBase;
            sectionMap[i].VirtualAddress = section->VirtualAddress;
            sectionMap[i].Size = section->Misc.VirtualSize;
            kprintf("Section complete");
        }

        NTSTATUS status = setupDll();

        //NTSTATUS status = ResolveImporting(targetProcess, baseAddress, ntHeaders, kernelDllBuffer);


        //NTSTATUS status = ResolveRelocationsWithSeparateSections(Dll, sectionMap, numberOfSections, target);
        //if (NT_SUCCESS(status))
            //kprintf("Relocations resolved successfully!\n");
        //else
        //{
            //kprintf("Failed to resolve relocations: 0x%x\n", status);
            //return STATUS_UNSUCCESSFUL;
        //}



        *MappedAddress = ntHeaders->OptionalHeader.AddressOfEntryPoint;
        return STATUS_SUCCESS;*/
    }


	NTSTATUS TriggerDllStart()
	{
		return STATUS_SUCCESS;
	}




}

