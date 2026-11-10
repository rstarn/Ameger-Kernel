#pragma once

#include <ntifs.h>

typedef struct _AMEGER_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    ULONG         _pad0;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    KPRIORITY     Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    KWAIT_REASON  WaitReason;
    ULONG         _pad1;
} AMEGER_SYSTEM_THREAD_INFORMATION, *PAMEGER_SYSTEM_THREAD_INFORMATION;

C_ASSERT(sizeof(AMEGER_SYSTEM_THREAD_INFORMATION) == 0x50);

typedef struct _AMEGER_SYSTEM_PROCESS_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG         HardFaultCount;
    ULONG         NumberOfThreadsHighWatermark;
    ULONGLONG     CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY     BasePriority;
    HANDLE        UniqueProcessId;
    HANDLE        InheritedFromUniqueProcessId;
    ULONG         HandleCount;
    ULONG         SessionId;
    ULONG_PTR     UniqueProcessKey;
    SIZE_T        PeakVirtualSize;
    SIZE_T        VirtualSize;
    ULONG         PageFaultCount;
    SIZE_T        PeakWorkingSetSize;
    SIZE_T        WorkingSetSize;
    SIZE_T        QuotaPeakPagedPoolUsage;
    SIZE_T        QuotaPagedPoolUsage;
    SIZE_T        QuotaPeakNonPagedPoolUsage;
    SIZE_T        QuotaNonPagedPoolUsage;
    SIZE_T        PagefileUsage;
    SIZE_T        PeakPagefileUsage;
    SIZE_T        PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    AMEGER_SYSTEM_THREAD_INFORMATION Threads[1];
} AMEGER_SYSTEM_PROCESS_INFORMATION, *PAMEGER_SYSTEM_PROCESS_INFORMATION;

C_ASSERT(FIELD_OFFSET(AMEGER_SYSTEM_PROCESS_INFORMATION, Threads) == 0x100);

typedef struct _AMEGER_THREAD_ENTRY {
    ULONG ThreadId;
    ULONG State;
    ULONG WaitReason;
    ULONG _pad;
} AMEGER_THREAD_ENTRY, *PAMEGER_THREAD_ENTRY;

NTSTATUS AmegerSnapshotThreads(_In_ ULONG ProcessId,
                               _Outptr_result_buffer_(*Count) PAMEGER_THREAD_ENTRY *Entries,
                               _Out_ PULONG Count);

VOID AmegerFreeThreads(_In_opt_ PAMEGER_THREAD_ENTRY Entries);
