#include "Information.h"
#include "../../NT/Definitions.h"

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_      ULONG SystemInformationClass,
    _Inout_   PVOID SystemInformation,
    _In_      ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

NTSTATUS
AmegerSnapshotThreads(_In_ ULONG ProcessId,
                      _Outptr_result_buffer_(*Count) PAMEGER_THREAD_ENTRY *Entries,
                      _Out_ PULONG Count)
{
    NTSTATUS status;
    ULONG len = 0;
    ULONG used = 0;
    ULONG offset = 0;
    PAMEGER_SYSTEM_PROCESS_INFORMATION spi = NULL;
    PAMEGER_SYSTEM_PROCESS_INFORMATION cur;

    if (Entries == NULL || Count == NULL)
        return STATUS_INVALID_PARAMETER;

    *Entries = NULL;
    *Count = 0;

    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &len);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return status;
    if (len < sizeof(AMEGER_SYSTEM_PROCESS_INFORMATION))
        return STATUS_INVALID_PARAMETER;

    len += 0x10000;
    spi = (PAMEGER_SYSTEM_PROCESS_INFORMATION)ExAllocatePool2(
        POOL_FLAG_PAGED, len, AMEGER_TAG_LOOKUP);
    if (spi == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    used = len;
    status = ZwQuerySystemInformation(SystemProcessInformation, spi, len, &used);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(spi, AMEGER_TAG_LOOKUP);
        return status;
    }
    if (used > len)
        used = len;

    status = STATUS_NOT_FOUND;
    for (;;) {
        ULONG entrySize;
        ULONG maxThreads;
        ULONG n;
        ULONG i;
        PAMEGER_THREAD_ENTRY out;

        if (offset + FIELD_OFFSET(AMEGER_SYSTEM_PROCESS_INFORMATION, Threads) > used)
            break;

        cur = (PAMEGER_SYSTEM_PROCESS_INFORMATION)((PUINT8)spi + offset);

        entrySize = (cur->NextEntryOffset != 0) ? cur->NextEntryOffset
                                                : (used - offset);
        if ((SIZE_T)entrySize <=
            (SIZE_T)FIELD_OFFSET(AMEGER_SYSTEM_PROCESS_INFORMATION, Threads))
            break;

        if ((ULONG_PTR)cur->UniqueProcessId == (ULONG_PTR)ProcessId) {
            maxThreads = (entrySize -
                          FIELD_OFFSET(AMEGER_SYSTEM_PROCESS_INFORMATION, Threads)) /
                         sizeof(AMEGER_SYSTEM_THREAD_INFORMATION);
            n = cur->NumberOfThreads;
            if (n > maxThreads)
                n = maxThreads;
            if (n == 0) {
                status = STATUS_NOT_FOUND;
                break;
            }

            out = (PAMEGER_THREAD_ENTRY)ExAllocatePool2(
                POOL_FLAG_PAGED, (SIZE_T)n * sizeof(AMEGER_THREAD_ENTRY),
                AMEGER_TAG_LOOKUP);
            if (out == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            for (i = 0; i < n; i++) {
                out[i].ThreadId = (ULONG)(ULONG_PTR)cur->Threads[i].ClientId.UniqueThread;
                out[i].State = cur->Threads[i].ThreadState;
                out[i].WaitReason = (ULONG)cur->Threads[i].WaitReason;
                out[i]._pad = 0;
            }

            *Entries = out;
            *Count = n;
            status = STATUS_SUCCESS;
            break;
        }

        if (cur->NextEntryOffset == 0)
            break;
        if (cur->NextEntryOffset >= used - offset)
            break;
        offset += cur->NextEntryOffset;
    }

    ExFreePoolWithTag(spi, AMEGER_TAG_LOOKUP);
    return status;
}

VOID
AmegerFreeThreads(_In_opt_ PAMEGER_THREAD_ENTRY Entries)
{
    if (Entries != NULL)
        ExFreePoolWithTag(Entries, AMEGER_TAG_LOOKUP);
}
