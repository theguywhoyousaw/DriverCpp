#include "Mem.h"

namespace Mem
{
    //UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;


    UINT32 GetUserDirectoryTableBaseOffset()
    {
        //RTL_OSVERSIONINFOW ver = { 0 };
        //RtlGetVersion(&ver);
        return 0x0388;
        /*
        switch (ver.dwBuildNumber)
        {
        case WINDOWS_1803:
            return 0x0278;
            break;
        case WINDOWS_1809:
            return 0x0278;
            break;
        case WINDOWS_1903:
            return 0x0280;
            break;
        case WINDOWS_1909:
            return 0x0280;
            break;
        case WINDOWS_2004:
            return 0x0388;
            break;
        case WINDOWS_20H2:
            return 0x0388;
            break;
        case WINDOWS_21H1:
            return 0x0388;
            break;
        default:
            return 0x0388;
        }*/
    }

    ULONG_PTR GetProcessCr3(PEPROCESS pProcess)
    {
        PUCHAR process = (PUCHAR)pProcess;
        ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
        if (process_dirbase == 0)
        {
            UINT32 UserDirOffset = GetUserDirectoryTableBaseOffset();
            ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
            return process_userdirbase;
        }
        return process_dirbase;
    }
    ULONG_PTR GetProcessCr3Nigger(PEPROCESS pProcess)
    {
        PUCHAR process = (PUCHAR)pProcess;
        ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
        return process_dirbase;
    }


    ULONG_PTR GetKernelDirBase()
    {
        PUCHAR process = (PUCHAR)PsGetCurrentProcess();
        ULONG_PTR cr3 = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
        return cr3;
    }

    extern "C" NTKERNELAPI VOID NTAPI KiStackAttachProcess(
        PKPROCESS Process,
        PKAPC_STATE ApcState,
        ULONG_PTR Flags
    );
    extern "C" void __writecr3(UINT64 newCr3);
    extern "C" UINT64 __readcr3(void);

    NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
    {
        MM_COPY_ADDRESS AddrToRead = { 0 };
        AddrToRead.PhysicalAddress.QuadPart = (UINT64)TargetAddress;
        return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
    }

    NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
    {
        if (!TargetAddress)
            return STATUS_UNSUCCESSFUL;

        PHYSICAL_ADDRESS AddrToWrite = { 0 };
        AddrToWrite.QuadPart = (UINT64)TargetAddress;
        if (!AddrToWrite.QuadPart || !Size) { return STATUS_UNSUCCESSFUL; }
        PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

        if (!pmapped_mem)
            return STATUS_UNSUCCESSFUL;

        memcpy(pmapped_mem, lpBuffer, Size);

        *BytesWritten = Size;
        MmUnmapIoSpace(pmapped_mem, Size);
        return STATUS_SUCCESS;
    }

    UINT64 TranslateLinearAddress(UINT64 directoryTableBase, UINT64 virtualAddress) {
        directoryTableBase &= ~0xf;

        UINT64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
        UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
        UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
        UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
        UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

        SIZE_T readsize = 0;
        UINT64 pdpe = 0;
        ReadPhysicalAddress((PVOID)(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
        if (~pdpe & 1)
            return 0;

        UINT64 pde = 0;
        ReadPhysicalAddress((PVOID)((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
        if (~pde & 1)
            return 0;

        /* 1GB large page, use pde's 12-34 bits */
        if (pde & 0x80)
            return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

        UINT64 pteAddr = 0;
        ReadPhysicalAddress((PVOID)((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
        if (~pteAddr & 1)
            return 0;

        /* 2MB large page */
        if (pteAddr & 0x80)
            return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

        virtualAddress = 0;
        ReadPhysicalAddress((PVOID)((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
        virtualAddress &= PMASK;

        if (!virtualAddress)
            return 0;

        return virtualAddress + pageOffset;
    }

    NTSTATUS ReadVirtual(UINT64 dirbase, UINT64 address, UINT8* buffer_a, SIZE_T size, SIZE_T* read)
    {
        UINT64 paddress = TranslateLinearAddress(dirbase, address);
        return ReadPhysicalAddress((PVOID)paddress, buffer_a, size, read);
    }

    NTSTATUS WriteVirtual(UINT64 dirbase, UINT64 address, UINT8* buffer_a, SIZE_T size, SIZE_T* written)
    {
        UINT64 paddress = TranslateLinearAddress(dirbase, address);
        if (!paddress) { return STATUS_UNSUCCESSFUL; }
        return WritePhysicalAddress((PVOID)paddress, buffer_a, size, written);
    }




    NTSTATUS ReadProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read)
    {
        kprintf("Reading: %p\n", Address);
        PEPROCESS pProcess = NULL;
        if (pid == 0)
        {
            kprintf("pid was 0");
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
        if (NtRet != STATUS_SUCCESS)
        {
            kprintf("PsLookupProcessByProcessId failed with NTSTATUS: 0x%08X\n", NtRet);
            
            kprintf("PsLookupProcessByProcessId was 0");
            return NtRet;
        }

        ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
        ObDereferenceObject(pProcess);

        SIZE_T CurOffset = 0;
        SIZE_T TotalSize = size;
        while (TotalSize)
        {

            UINT64 CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
            if (!CurPhysAddr) 
            { 
                kprintf("CurPhysAddr was 0");
                return STATUS_UNSUCCESSFUL;
            }

            ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
            SIZE_T BytesRead = 0;
            NtRet = ReadPhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
            TotalSize -= BytesRead;
            CurOffset += BytesRead;
            if (NtRet != STATUS_SUCCESS) break;
            if (BytesRead == 0) break;
        }

        *read = CurOffset;
        return NtRet;
    }



    NTSTATUS WriteProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written)
    {
        PEPROCESS pProcess = NULL;
        if (pid == 0) return STATUS_UNSUCCESSFUL;

        NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);

        if (NtRet != STATUS_SUCCESS) return NtRet;

        ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
        ObDereferenceObject(pProcess);

        SIZE_T CurOffset = 0;
        SIZE_T TotalSize = size;
        while (TotalSize)
        {
            UINT64 CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
            if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

            ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
            SIZE_T BytesWritten = 0;
            NtRet = WritePhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
            TotalSize -= BytesWritten;
            CurOffset += BytesWritten;
            if (NtRet != STATUS_SUCCESS) break;
            if (BytesWritten == 0) break;
        }

        *written = CurOffset;
        return NtRet;
    }

    FORCEINLINE ULONGLONG MiVirtualToPhysical(_In_ ULONGLONG DirectoryBase, _In_ ULONGLONG VirtualAddress)
    {
        ULONGLONG       table, PhysicalAddress = 0, selector, entry = 0;
        LONG            r, shift;
        SIZE_T          NumberOfBytesCopied;
        MM_COPY_ADDRESS MmAddress;

        table = DirectoryBase & PHY_ADDRESS_MASK;

        for (r = 0; r < 4; r++)
        {
            shift = 39 - (r * 9);
            selector = (VirtualAddress >> shift) & 0x1ff;
            NumberOfBytesCopied = 0;
            MmAddress.PhysicalAddress.QuadPart = table + selector * 8;

            if (!NT_SUCCESS(MmCopyMemory(&entry, MmAddress, sizeof(ULONGLONG), MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesCopied)))
            {
                kprintf("Copy fail | ");
                return PhysicalAddress;
            }

            if (!(entry & ENTRY_PRESENT_BIT))
            {
                kprintf("Paged out | ");
                return PhysicalAddress;
            }

            table = entry & PHY_ADDRESS_MASK;
            if (entry & ENTRY_PAGE_SIZE_BIT)
            {
                if (r == 1)
                {
                    table &= PHY_ADDRESS_MASK_1GB_PAGES;
                    table += VirtualAddress & VADDR_ADDRESS_MASK_1GB_PAGES;
                    PhysicalAddress = table;
                    return PhysicalAddress;
                }

                if (r == 2)
                {
                    table &= PHY_ADDRESS_MASK_2MB_PAGES;
                    table += VirtualAddress & VADDR_ADDRESS_MASK_2MB_PAGES;
                    PhysicalAddress = table;
                    return PhysicalAddress;
                }
            }
        }

        table += VirtualAddress & VADDR_ADDRESS_MASK_4KB_PAGES;
        PhysicalAddress = table;
        return PhysicalAddress;
    }

    FORCEINLINE NTSTATUS MiCopyPhysicalMemory(ULONGLONG PhysicalAddress, PVOID Buffer, SIZE_T NumberOfBytes, BOOLEAN DoWrite)
    {
        NTSTATUS         Status;
        SIZE_T           TotalBytes, BytesCopied, BytesToCopy;
        PVOID            MapSection;
        PHYSICAL_ADDRESS Address;

        Status = STATUS_INFO_LENGTH_MISMATCH;
        TotalBytes = NumberOfBytes;
        BytesCopied = 0;
        BytesToCopy = 0;
        MapSection = NULL;

        while (TotalBytes)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            Address.QuadPart = PhysicalAddress + BytesCopied;
            BytesToCopy = PHYSICAL_MAP_THRESHOLD(Address.QuadPart, TotalBytes);
            MapSection = MmMapIoSpaceEx(Address, BytesToCopy, PAGE_READWRITE);

            if (MapSection)
            {
                switch (DoWrite)
                {
                case TRUE:
                    RtlCopyMemory(MapSection, RtlOffsetToPointer(Buffer, BytesCopied), BytesToCopy);
                    break;
                case FALSE:
                    RtlCopyMemory(RtlOffsetToPointer(Buffer, BytesCopied), MapSection, BytesToCopy);
                    break;
                }

                MmUnmapIoSpace(MapSection, BytesToCopy);
                Status = STATUS_SUCCESS;
                BytesCopied += BytesToCopy;
                TotalBytes -= BytesToCopy;
            }

            if (Status != STATUS_SUCCESS) break;
        }

        return Status;
    }


    bool writeMem(PEPROCESS target, PVOID Destination, PVOID Source, SIZE_T NumberOfBytes)
    {
        /*if (!offset_arg) {
            kprintf("Offset null in write\n");
            return; }
        ULONG_PTR Base = 0x0;
        SIZE_T read;
        NTSTATUS status = WriteProcessMemory(procID, (PVOID)(Base + offset_arg), buffer_, size, &read);
        if (status != STATUS_SUCCESS)
        {
            kprintf("WriteProcessMemory failed with NTSTATUS: 0x%08X\n", status);
        }*/
        NTSTATUS Status = STATUS_SUCCESS;
        PEPROCESS ProcessToLock = NULL;
        PHYSICAL_ADDRESS PhysicalAddress;
        PVOID MappedAddress = NULL;

        SIZE_T BytesRemaining = NumberOfBytes;
        SIZE_T BytesToWrite = 0;
        ULONGLONG DestAddr = (ULONGLONG)Destination;
        ULONGLONG SrcAddr = (ULONGLONG)Source;

        // Step 1: Lookup the process by process ID (if Destination is in user-mode process)

        ProcessToLock = target;

        // Step 2: Check if the process is terminating
        Status = STATUS_PROCESS_IS_TERMINATING;
        PEX_RUNDOWN_REF rd = (EX_RUNDOWN_REF*)((UINT64)(&*ProcessToLock) + 0x458);
        
        // Step 2: Check if the process is terminating
        if (ExAcquireRundownProtection(rd) == FALSE){//ExAcquireRundownProtection(rd) == FALSE)
            kprintf("[-] Process is terminating.\n");
            ObDereferenceObject(ProcessToLock);
            return false;
        }

        // Ensure Source (kernel memory) is valid — it's a kernel buffer, so no need to check using MmIsAddressValid
        if ((ULONGLONG)Source <= 10000) {
            kprintf("[-] Invalid source address.\n");
            ExReleaseRundownProtection(rd);
            ObDereferenceObject(ProcessToLock);
            return false;
        }

        // Step 3: Validate that Destination is a user-mode or kernel-mode address
        if ((ULONGLONG)Destination <= 10000) {
            kprintf("[-] Invalid destination address.\n");
            ExReleaseRundownProtection(rd);
            ObDereferenceObject(ProcessToLock);
            return false;
        }

        // Step 4: Translate Destination virtual address to physical address
        // This assumes that the Destination address might be a user-mode virtual address.
        //PhysicalAddress = MmGetPhysicalAddress(Destination);
        while (BytesRemaining > 0) {
            // Step 4: Calculate the current page boundary and the number of bytes to write in this iteration
            ULONGLONG PageOffset = DestAddr % PAGE_SIZE;  // Get offset within the page
            BytesToWrite = min(PAGE_SIZE - PageOffset, BytesRemaining);  // Write up to the end of the page or remaining bytes

            // Step 5: Translate the current virtual address (DestAddr) to physical address
            PhysicalAddress.QuadPart = MiVirtualToPhysical(GetProcessCr3(target), DestAddr);
            if (PhysicalAddress.QuadPart == 0) {
                kprintf("[-] Failed to translate Destination address to physical.\n");
                ExReleaseRundownProtection(rd);
                ObDereferenceObject(ProcessToLock);
                return false;
            }

            // Step 6: Map the physical address for writing
            MappedAddress = MmMapIoSpace(PhysicalAddress, BytesToWrite, MmNonCached);
            if (MappedAddress == NULL) {
                kprintf("[-] Failed to map physical memory.\n");
                ExReleaseRundownProtection(rd);
                ObDereferenceObject(ProcessToLock);
                return false;
            }

            // Step 7: Perform the memory copy
            RtlCopyMemory(MappedAddress, (PVOID)Source, BytesToWrite);

            // Step 8: Unmap the physical memory after writing
            MmUnmapIoSpace(MappedAddress, BytesToWrite);

            // Step 9: Move to the next chunk/page
            BytesRemaining -= BytesToWrite;
            DestAddr += BytesToWrite;
            SrcAddr += BytesToWrite;
        }
        /*PhysicalAddress.QuadPart = MiVirtualToPhysical(GetProcessCr3Nigger(Processsss), (ULONGLONG)Destination);
        //MmCopyMemory()
        if (PhysicalAddress.QuadPart == 0) {
            kprintf("[-] Failed to translate Destination address to physical.\n");
            ObDereferenceObject(ProcessToLock);
            return false;
        }
        //kprintf("[+] Physical address of Destination: 0x%llX\n", PhysicalAddress.QuadPart);
        //(void)NumberOfBytes;
        //(void)MappedAddress;
        // Step 5: Map the physical address into kernel space for writing
        MappedAddress = MmMapIoSpace(PhysicalAddress, NumberOfBytes, MmNonCached);
        if (MappedAddress == NULL) {
            kprintf("[-] Failed to map physical memory.\n");
            ObDereferenceObject(ProcessToLock);
            return false;
        }

        //Something gotta be wrong with params passed to RtlCopyMemory, figure out what
        //https://chatgpt.com/share/67103611-5b58-8009-aceb-af8aa33a879e

        // Step 6: Perform the memory copy from kernel Source to the mapped physical address
        RtlCopyMemory(MappedAddress, Source, NumberOfBytes);

        // Step 7: Unmap the physical memory after the write
        MmUnmapIoSpace(MappedAddress, NumberOfBytes);
        */
        ExReleaseRundownProtection(rd);
        ObDereferenceObject(ProcessToLock);

        //kprintf("[+] Successfully wrote %llu bytes to the destination physical address.\n", NumberOfBytes);
        //kprintf("Mem write success\n");
        return true;

        /*NTSTATUS         Status;
        PHYSICAL_ADDRESS Address;
        PEPROCESS        ProcessToLock;

        //
        // TODO: Should the add additional check
        // to process object.
        //

        Status = STATUS_ACCESS_VIOLATION;
        PEPROCESS Process;
        PsLookupProcessByProcessId((HANDLE)procID, &Process);
        ProcessToLock = Process;

        if ((ULONGLONG)Source <= 10000) {
            kprintf("[-] Source address is too low: %p\n", Source);
            return Status;
        }

        if ((ULONGLONG)Destination <= 10000) {
            kprintf("[-] Destination address is too low: %p\n", Destination);
            return Status;
        }

        if (RtlOffsetToPointer(Source, NumberOfBytes) < (PCHAR)Source) {
            kprintf("[-] Source address overflow: %p + %llu\n", Source, NumberOfBytes);
            return Status;
        }

        if (RtlOffsetToPointer(Destination, NumberOfBytes) < (PCHAR)Destination) {
            kprintf("[-] Destination address overflow: %p + %llu\n", Destination, NumberOfBytes);
            return Status;
        }


        Status = STATUS_INVALID_ADDRESS;

        if (!MmIsAddressValid(Source))
        {
            kprintf("[-] Invalid Address.");
            return Status;
        }

        // ==================================================================================
        // Make sure the process still has an address space.
        // ==================================================================================
        Status = STATUS_PROCESS_IS_TERMINATING;
        PEX_RUNDOWN_REF rd = (EX_RUNDOWN_REF*)(&ProcessToLock) + 0x458;
        if (ExAcquireRundownProtection(rd) == FALSE)
        {
            kprintf("[-] Process already terminating.");
            return Status;
        }

#if 1
        Address.QuadPart = MiVirtualToPhysical(GetProcessCr3(Process), (ULONGLONG)Destination);
#else
        KAPC_STATE ApcState;
        KeStackAttachProcess((PRKPROCESS)&ProcessToLock->Pcb, &ApcState);
        Address = MmGetPhysicalAddress(Destination);
        KeUnstackDetachProcess(&ApcState);
#endif

        if (!Address.QuadPart)
        {
            kprintf("[-] Failed Translating Source Address.");
            goto CompleteService;
        }

        Status = MiCopyPhysicalMemory(Address.QuadPart, Source, NumberOfBytes, TRUE);

    CompleteService:

        // ==================================================================================
        // Indicate that the vm operation is complete.
        // ==================================================================================
        ExReleaseRundownProtection(rd);
        return Status;*/
    }
    

    bool readMem(PEPROCESS target, PVOID Source, PVOID Destination, SIZE_T NumberOfBytes)
    {
        /*ULONG_PTR Base = 0x0;
        SIZE_T read;
        if (offset_arg)
        {
            NTSTATUS status = ReadProcessMemory(procID, (PVOID)(Base + offset_arg), buffer_, size, &read);
            if (status != STATUS_SUCCESS)
            {
                kprintf("ReadProcessMemory failed with NTSTATUS: 0x%08X\n", status);
                return false;
            }
            return true;
        }
        else
        {
            kprintf("Offset null in read\n");
            return false;
        }*/
        NTSTATUS         Status;
        PHYSICAL_ADDRESS Address;
        PEPROCESS        ProcessToLock;
        SIZE_T BytesRemaining = NumberOfBytes;
        SIZE_T BytesToRead = 0;
        ULONGLONG SrcAddr = (ULONGLONG)Source;
        ULONGLONG DestAddr = (ULONGLONG)Destination;
        // ==================================================================================
        // TODO: Should the add additional check
        // to process object.
        // ==================================================================================
        Status = STATUS_ACCESS_VIOLATION;
        
        ProcessToLock = target;
        if ((ULONGLONG)Source <= 10000) {
            kprintf("[-] Source address is too low: %p\n", Source);
            return false;
        }
        if ((ULONGLONG)Destination <= 10000) {
            kprintf("[-] Destination address is too low: %p\n", Destination);
            return false;
        }
        if (RtlOffsetToPointer(Source, NumberOfBytes) < (PCHAR)Source) {
            kprintf("[-] Source address overflow: %p + %llu\n", Source, NumberOfBytes);
            return false;
        }
        if (RtlOffsetToPointer(Destination, NumberOfBytes) < (PCHAR)Destination) {
            kprintf("[-] Destination address overflow: %p + %llu\n", Destination, NumberOfBytes);
            return false;
        }
        if (RtlOffsetToPointer(Source, NumberOfBytes) > (PCHAR)MM_HIGHEST_USER_ADDRESS) {
            kprintf("[-] Source address exceeds user-mode limit: %p\n", RtlOffsetToPointer(Source, NumberOfBytes));
            return false;
        }

        Status = STATUS_INVALID_ADDRESS;

        if (!MmIsAddressValid(Destination))
        {
            kprintf("[-] Invalid Address.");
            return false;
        }
        while (BytesRemaining > 0) {
            // Calculate the current page boundary and the number of bytes to read in this iteration
            ULONGLONG PageOffset = SrcAddr % PAGE_SIZE;  // Offset within the page
            BytesToRead = min(PAGE_SIZE - PageOffset, BytesRemaining);  // Read up to the page boundary or remaining bytes
            MM_COPY_ADDRESS MmAddress;
            SIZE_T NumberOfBytesCopied = 0;

            // Step 4: Translate the current virtual address (SrcAddr) to a physical address
            Address.QuadPart = MiVirtualToPhysical(GetProcessCr3(target), SrcAddr);
            if (Address.QuadPart == 0) {
                kprintf("[-] Failed to translate Source address to physical, attempting memcopy\n");
                //KAPC_STATE apcState;
                //KiStackAttachProcess(target, &apcState, )
                MmAddress.VirtualAddress = (PVOID)SrcAddr;
                Status = MmCopyMemory((PVOID)DestAddr, MmAddress, BytesToRead, MM_COPY_MEMORY_VIRTUAL, &NumberOfBytesCopied);
                if (NumberOfBytesCopied == 0 && Status != STATUS_SUCCESS)
                {
                    kprintf("[-] MmCopyMemory(V) failed: Status = 0x%08X\n", Status);
                    kprintf("Attempting force attach\n");
                    UINT64 originalCr3 = __readcr3();
                    __writecr3(GetProcessCr3(target)); //Force attach
                    Status = MmCopyMemory((PVOID)DestAddr, MmAddress, BytesToRead, MM_COPY_MEMORY_VIRTUAL, &NumberOfBytesCopied);
                    __writecr3(originalCr3); //Detach
                    if (NumberOfBytesCopied > 0)
                    {
                        BytesRemaining -= BytesToRead;
                        SrcAddr += BytesToRead;
                        DestAddr += BytesToRead;
                        continue;
                    }
                    else
                    {
                        kprintf("Read failed\n");
                        return false;
                    }
                }
                else
                {
                    BytesRemaining -= BytesToRead;
                    SrcAddr += BytesToRead;
                    DestAddr += BytesToRead;
                    continue;
                }
            }

            // Step 5: Perform the memory copy from the physical address
            
            MmAddress.PhysicalAddress = Address;
            

            Status = MmCopyMemory((PVOID)DestAddr, MmAddress, BytesToRead, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesCopied);
            if (!NT_SUCCESS(Status)) {
                kprintf("[-] MmCopyMemory failed: 0x%08X\n", Status);
                return false;
            }

            // Step 6: Move to the next chunk/page
            BytesRemaining -= BytesToRead;
            SrcAddr += BytesToRead;
            DestAddr += BytesToRead;
        }
        /*Address.QuadPart = MiVirtualToPhysical(GetProcessCr3Nigger(Process), (ULONGLONG)Source); //Process->Pcb.DirectoryTableBase
        Status = STATUS_CONFLICTING_ADDRESSES;
        if (Address.QuadPart)
        {
            MM_COPY_ADDRESS MmAddress;
            MmAddress.PhysicalAddress = Address;
            SIZE_T NumberOfBytesCopied;

            Status = MmCopyMemory(Destination, MmAddress, NumberOfBytes, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesCopied);
        }*/

        // ==================================================================================
        // Indicate that the vm operation is complete.
        // ==================================================================================
        //kprintf("Mem read success\n");
        return true;
    }

    bool CopyUsermodeStructureToKernel(PEPROCESS target, PVOID StructureLocation, SIZE_T StructureSize, PVOID StructureReturn)
    {
        if (!readMem(target, StructureLocation, StructureReturn, StructureSize))
            return false;
        return true;
    }

}