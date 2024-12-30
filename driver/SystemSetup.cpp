#include "SystemSetup.h"

namespace sysData
{
}

namespace sysConfig
{
    bool acIsKernel = false;
    bool acIsUsermode = false;
    bool cheatIsInternal = false;
    char* targetName;
    char* targetNameTrimmed;
    ULONG processID;

    
}

namespace sysInternal
{
    ULONG GetWindowsVersion()
    {
        RTL_OSVERSIONINFOW ver = { 0 };
        ver.dwOSVersionInfoSize = sizeof(ver);
        if (RtlGetVersion(&ver) != STATUS_SUCCESS)
        {
            return 0x0;
        }
        return ver.dwBuildNumber;
    }

    NTSTATUS ResolveOffsets(ULONG vnum)
    {
        if (vnum == 19045)//22h2
        {

        }
        else if (vnum == 19044) //21h2
        {

        }
        else if (vnum == 19043) //21h1
        {

        }
        else if (vnum == 19042) //20h2
        {

        }
        else if (vnum == 19041) //2004
        {

        }
        else if (vnum == 18362) //1909
        {

        }
        else
            return STATUS_UNSUCCESSFUL;
        return STATUS_SUCCESS;
    }
}

namespace sysSetup
{
    NTSTATUS initialize()
    {
        //Non-specific code
        ULONG versionNum;
        if ((versionNum = sysInternal::GetWindowsVersion()) == 0)
        {
            return STATUS_UNSUCCESSFUL;
        }
        
        if (!NT_SUCCESS(sysInternal::ResolveOffsets(versionNum)))
        {
            return STATUS_UNSUCCESSFUL;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS CreateConfig(char* ProcessName, bool IsKernelAC, bool IsInternalCheat)
    {
        sysConfig::acIsKernel = IsKernelAC;
        sysConfig::acIsUsermode = !sysConfig::acIsKernel;
        sysConfig::cheatIsInternal = IsInternalCheat;
        sysConfig::targetName = ProcessName; //Target string -> CalculatorApp.exe
        ProcessName[14] = '\0';
        sysConfig::targetNameTrimmed = ProcessName; //Trim the string for EPROCESS struct -> CalculatorApp.
        return STATUS_SUCCESS;
    }

    NTSTATUS fetchFileBytes(PCWSTR filePath, PVOID* buffer, PSIZE_T bufferSize)
    {
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
}