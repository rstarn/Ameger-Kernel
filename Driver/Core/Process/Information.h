#pragma once

#include <ntifs.h>

typedef struct _INJECTOR_SYSTEM_THREAD_INFORMATION {
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
} INJECTOR_SYSTEM_THREAD_INFORMATION, *PINJECTOR_SYSTEM_THREAD_INFORMATION;

C_ASSERT(sizeof(INJECTOR_SYSTEM_THREAD_INFORMATION) == 0x50);

typedef struct _INJECTOR_SYSTEM_PROCESS_INFORMATION {
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
    INJECTOR_SYSTEM_THREAD_INFORMATION Threads[1];
} INJECTOR_SYSTEM_PROCESS_INFORMATION, *PINJECTOR_SYSTEM_PROCESS_INFORMATION;

C_ASSERT(FIELD_OFFSET(INJECTOR_SYSTEM_PROCESS_INFORMATION, Threads) == 0x100);

typedef struct _INJECTOR_THREAD_ENTRY {
    ULONG ThreadId;
    ULONG State;
    ULONG WaitReason;
    ULONG _pad;
} INJECTOR_THREAD_ENTRY, *PINJECTOR_THREAD_ENTRY;

NTSTATUS InjectorSnapshotThreads(_In_ ULONG ProcessId,
                               _Outptr_result_buffer_(*Count) PINJECTOR_THREAD_ENTRY *Entries,
                               _Out_ PULONG Count);

VOID InjectorFreeThreads(_In_opt_ PINJECTOR_THREAD_ENTRY Entries);
