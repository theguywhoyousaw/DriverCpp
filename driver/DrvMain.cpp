#include "Incloods.h"
#include "SystemSetup.h"
#include "Agent.h"



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

    PCHAR ProcessName = "notepad.exe";
    bool isKMode = false;
    bool isUMode = false;
    if (!NT_SUCCESS(sysSetup::CreateConfig(ProcessName, isKMode, isUMode)))
        return STATUS_UNSUCCESSFUL;
    if (!NT_SUCCESS(sysSetup::initialize()))
        return STATUS_UNSUCCESSFUL;
    if (!NT_SUCCESS(sysSetup::fetchFileBytes(L"\\??\\C:\\Users\\Billy\\Desktop\\CS2-sxy.dll", &dll, &dllSizeRaw)))
        return STATUS_UNSUCCESSFUL;
    //WaitForProcess

    if (sysConfig::acIsUsermode)
    {
        PEPROCESS target = (PEPROCESS)UmAgent::PollUntilProcess();
        (void)target;
        //UmAgent::inject()
    }



    return STATUS_SUCCESS;
}