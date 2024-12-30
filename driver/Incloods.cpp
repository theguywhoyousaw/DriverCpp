#include "includes.h"

void kprintf(const char* format, ...) {
    va_list args;
    va_start(args, format);  // Initialize the va_list to retrieve arguments

    // Forward the arguments to DbgPrintEx with a fixed DPFLTR level
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, args);

    va_end(args);  // Clean up the va_list
}