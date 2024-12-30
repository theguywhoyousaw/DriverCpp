#pragma once
#include "Incloods.h"

#define SWIZZLE_KEY 0xCCCCCCCC

PVOID ObfuscatePointer(PVOID ptr) {
    return (PVOID)((ULONG_PTR)ptr ^ SWIZZLE_KEY);
}

PVOID DeobfuscatePointer(PVOID obfPtr) {
    return (PVOID)((ULONG_PTR)obfPtr ^ SWIZZLE_KEY);
}

//MapDllToProcess