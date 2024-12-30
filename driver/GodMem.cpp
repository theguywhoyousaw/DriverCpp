#include "GodMem.h"
namespace GodMem
{
    PVOID ObfuscatePointer(PVOID ptr) {
        return (PVOID)((ULONG_PTR)ptr ^ SWIZZLE_KEY);
    }

    PVOID DeobfuscatePointer(PVOID obfPtr) {
        return (PVOID)((ULONG_PTR)obfPtr ^ SWIZZLE_KEY);
    }
}