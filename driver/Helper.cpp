#include "Helper.h"

namespace Helper
{
    namespace internalData //Foward decl
    {
        bool saveData(_KTHREAD*, _ETHREAD*);
        void wipeData(_KTHREAD*, _ETHREAD*);
        void restoreData(_KTHREAD*, _ETHREAD*);
        extern PEPROCESS eProcessEntry;
    }
}

namespace Helper
{
    namespace Config
    {
        bool acIsKernel = false;
        bool acIsUsermode = false;
        bool cheatIsInternal = false;
        char* targetName;
        char* targetNameTrimmed;
        ULONG processID;

        NTSTATUS CreateConfig(char* ProcessName, bool IsKernelAC, bool IsInternalCheat)
        {
            acIsKernel = IsKernelAC;
            acIsUsermode = !acIsKernel;
            cheatIsInternal = IsInternalCheat;
            targetName = ProcessName; //Target string -> CalculatorApp.exe
            ProcessName[14] = '\0';
            targetNameTrimmed = ProcessName; //Trim the string for EPROCESS struct -> CalculatorApp.
            return STATUS_SUCCESS;
        }
    }

	long windowsVersion = 0;
    void* holder = NULL;

    typedef BOOLEAN(*func)(const _HANDLE_TABLE*, const HANDLE, const _HANDLE_TABLE_ENTRY*);
    func ExDestroyHandle;

	NTSTATUS GetWindowsVersion()
	{
		RTL_OSVERSIONINFOW ver = { 0 };
		ver.dwOSVersionInfoSize = sizeof(ver);
        if (RtlGetVersion(&ver) != STATUS_SUCCESS)
        {
            return STATUS_UNSUCCESSFUL;
        }
		windowsVersion = ver.dwBuildNumber;
        return STATUS_SUCCESS;
	}

    void SleepInMilliseconds(LONG milliseconds) {
        LARGE_INTEGER interval;
        // Convert milliseconds to 100-nanosecond intervals and make it negative
        interval.QuadPart = -(10 * 1000 * milliseconds);  // 1000 * 10 for 100ns intervals

        // Call KeDelayExecutionThread to sleep the current thread
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    UINT64 find_eprocess(char* process_name)
    {
        UINT64 ActiveProcessLinks_o = 0x448;
        UINT64 ImageFileName_o = 0x5a8;
        UINT64 list_head = *(UINT64*)((UINT64)PsInitialSystemProcess + ActiveProcessLinks_o);
        UINT64 list_current = list_head;

        UINT64 result = NULL;

        do
        {
            UINT64 list_entry = list_current - ActiveProcessLinks_o;

            if (!_stricmp(process_name, (char*)(list_entry + ImageFileName_o)))
            {
                result = list_entry; //Finds last entry
            }

            list_current = *(UINT64*)list_current;
        } while (list_current != list_head);

        if(result != NULL)
            Config::processID = *(long*)((UINT64)result + 0x440);

        return result;
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

    NTSTATUS HideSelf()
    {
        NTSTATUS callret; //Generic response info

        holder = PsGetCurrentThread();
        _KTHREAD* kCurrentThread = (_KTHREAD*)holder;
        _ETHREAD* eCurrentThread = (_ETHREAD*)holder;

        if (!internalData::saveData(kCurrentThread, eCurrentThread))
        {
            kprintf("Windows version is not compatible\n");
            return STATUS_UNSUCCESSFUL;
        }

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
            return STATUS_UNSUCCESSFUL;
        }

        HANDLE threadID = PsGetCurrentThreadId();
        callret = removeThreadEproc(threadID, internalData::eProcessEntry);
        if (callret != STATUS_SUCCESS) { kprintf("Failed unlink\n"); return STATUS_UNSUCCESSFUL; }

        if (Config::acIsKernel)
        {
            callret = UnlinkPSPCid();
            if (callret != STATUS_SUCCESS) { kprintf("Failed pspcid\n"); return STATUS_UNSUCCESSFUL; }
        }




        kprintf("Everything looks good, 'going dark' \n");
        internalData::wipeData(kCurrentThread, eCurrentThread);
        //DebugMessageAddress(kCurrentThread->StackBase);
        //DebugMessageAddress(eCurrentThread->StartAddress);
        //internalData::restoreData(kCurrentThread, eCurrentThread);
        //DebugMessageAddress(kCurrentThread->StackBase);
        //DebugMessageAddress(eCurrentThread->StartAddress);

        return STATUS_SUCCESS;
    }
    bool shutdownDriver()
    {
        //NTSTATUS callret;
        _KTHREAD* kCurrentThread = (_KTHREAD*)holder;
        _ETHREAD* eCurrentThread = (_ETHREAD*)holder;
        internalData::restoreData(kCurrentThread, eCurrentThread);
        return true;
    }

    NTSTATUS ResolveSyscalls()
    {

        return STATUS_SUCCESS;
    }
    UINT64 PollUntilProcess()
    {
        while (1)
        {
            UINT64 processBase = Helper::find_eprocess(Helper::Config::targetNameTrimmed);
            if (processBase)
            {
                return processBase;
            }
            SleepInMilliseconds(50);
        }
    }

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

        bool saveData(_KTHREAD* kt, _ETHREAD* et)
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
            if (windowsVersion == 19045)
            {
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
                return true;
            }
            return false;
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
}

