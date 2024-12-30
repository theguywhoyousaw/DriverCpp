#include "UmAgent.h"

namespace UmAgentInternal
{
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

        if (result != NULL)
            sysConfig::processID = *(long*)((UINT64)result + 0x440);

        return result;
    }

    void SleepInMilliseconds(LONG milliseconds) {
        LARGE_INTEGER interval;
        // Convert milliseconds to 100-nanosecond intervals and make it negative
        interval.QuadPart = -(10 * 1000 * milliseconds);  // 1000 * 10 for 100ns intervals

        // Call KeDelayExecutionThread to sleep the current thread
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
}

namespace UmAgent
{
	UINT64 PollUntilProcess()
	{
        while (1)
        {
            UINT64 processBase = UmAgentInternal::find_eprocess(sysConfig::targetNameTrimmed);
            if (processBase)
            {
                return processBase;
            }
            UmAgentInternal::SleepInMilliseconds(50);
        }
	}
}