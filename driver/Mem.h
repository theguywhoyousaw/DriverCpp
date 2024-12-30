#pragma once
#include "includes.h"

#define PHYSICAL_MAP_THRESHOLD(Address, TotalSize) ((PAGE_SIZE - ((ULONGLONG)PAGE_SIZE - (Address & 0xFFF) & 0xFFF) < (TotalSize)) ? (PAGE_SIZE - (Address & 0xFFF)) : (TotalSize))

#define PAGE_OFFSET_SIZE                           12
#define PMASK                                      (~0xfull << 8) & 0xfffffffffull

#define PHY_ADDRESS_MASK                           0x000ffffffffff000ull
#define PHY_ADDRESS_MASK_1GB_PAGES                 0x000fffffc0000000ull
#define PHY_ADDRESS_MASK_2MB_PAGES                 0x000fffffffe00000ull
#define VADDR_ADDRESS_MASK_1GB_PAGES               0x000000003fffffffull
#define VADDR_ADDRESS_MASK_2MB_PAGES               0x00000000001fffffull
#define VADDR_ADDRESS_MASK_4KB_PAGES               0x0000000000000fffull
#define ENTRY_PRESENT_BIT                          1
#define ENTRY_PAGE_SIZE_BIT                        0x0000000000000080ull

namespace Mem
{
	bool readMem(PEPROCESS target, PVOID Source, PVOID Destination, SIZE_T NumberOfBytes);
	NTSTATUS MiReadSystemMemory(IN PVOID Source, OUT PVOID Destination, IN SIZE_T NumberOfBytes);
	bool writeMem(PEPROCESS target, PVOID Destination, PVOID Source, SIZE_T NumberOfBytes);
	bool CopyUsermodeStructureToKernel(PEPROCESS target, PVOID StructureLocation, SIZE_T StructureSize, PVOID StructureReturn);
}