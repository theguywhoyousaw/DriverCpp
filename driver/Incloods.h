#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>  // for __readmsr & _mm_clflush
#include <windef.h>
#include <ntimage.h>
#include <ntdef.h>
#include <stdarg.h> // For handling variadic arguments

#define combine( ptr, val ) ( (UINT64)ptr + (UINT64)val )
#define IA32_LSTAR 0xC0000082  // MSR for 64-bit system call entry
#define int32_t int
#define uint8_t unsigned char
#define uintptr_t unsigned long long
#define PAGE_OFFSET_SIZE 12
#define SystemModuleInformation 11  // For NtQuerySystemInformation
#define PAGE_READABLE (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

#define DLL_PROCESS_ATTACH 1
#define DLL_PROCESS_DETACH 0
#define DLL_THREAD_ATTACH  2
#define DLL_THREAD_DETACH  3

#pragma warning (disable : 4996) //Disable depreciation warning for AllocatePool

void kprintf(const char* format, ...);