#include "Mapping.h"
#include "../Channel/Channel.h"
#include "../../Process/Information.h"
#include "../../../NT/Definitions.h"
#include <stdarg.h>
#include <ntstrsafe.h>

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
#ifndef STATUS_CONFLICTING_ADDRESSES
#define STATUS_CONFLICTING_ADDRESSES ((NTSTATUS)0xC0000018L)
#endif
#ifndef STATUS_PROCESS_IS_TERMINATING
#define STATUS_PROCESS_IS_TERMINATING ((NTSTATUS)0xC000010AL)
#endif
#ifndef STATUS_NOT_READY
#define STATUS_NOT_READY       ((NTSTATUS)0xC00000A3L)
#endif
#ifndef STATUS_INVALID_DEVICE_STATE
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184L)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION   0x0008
#endif

NTKERNELAPI PPEB PsGetProcessPeb(_In_ PEPROCESS Process);

VOID
InjectorDiagLog(_In_ PCSTR Format, ...)
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    CHAR buf[512];
    va_list args;
    size_t len = 0;
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;

    va_start(args, Format);
    (void)RtlStringCchVPrintfA(buf, sizeof(buf), Format, args);
    va_end(args);

    if (!NT_SUCCESS(RtlStringCchLengthA(buf, sizeof(buf), &len)) || len == 0)
        return;

    RtlInitUnicodeString(&path, L"\\SystemRoot\\Temp\\injector_diag.log");
    InitializeObjectAttributes(&oa, &path,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    status = ZwCreateFile(&hFile,
                          FILE_APPEND_DATA | SYNCHRONIZE,
                          &oa, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL, 0);
    if (!NT_SUCCESS(status))
        return;

    (void)ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
                      buf, (ULONG)len, NULL, NULL);
    (void)ZwClose(hFile);
}

static BOOLEAN InjectorImageNameMatch(PCSTR Name)
{
    PCSTR want = INJECTOR_CLIENT_IMAGE_NAME;
    SIZE_T i = 0;
    if (Name == NULL) return FALSE;
    while (want[i] && Name[i] && i < 14) {
        CHAR a = Name[i], b = want[i];
        if (a >= 'A' && a <= 'Z') a = (CHAR)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (CHAR)(b + ('a' - 'A'));
        if (a != b) return FALSE;
        i++;
    }

    if (i == 14) return TRUE;
    return (Name[i] == '\0' && want[i] == '\0');
}

static BOOLEAN InjectorImageNamePrefixMatch(PCSTR Name, SIZE_T PrefixLen)
{
    PCSTR want = INJECTOR_CLIENT_IMAGE_NAME;
    SIZE_T i;

    if (Name == NULL) return FALSE;
    for (i = 0; i < PrefixLen; i++) {
        CHAR a = Name[i], b = want[i];
        if (a >= 'A' && a <= 'Z') a = (CHAR)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (CHAR)(b + ('a' - 'A'));
        if (a == '\0' || b == '\0' || a != b) return FALSE;
    }
    return TRUE;
}

NTSTATUS InjectorChannelMapIntoProcess(_In_ PEPROCESS Process)
{
    NTSTATUS status;
    HANDLE hSection;
    HANDLE hProcess = NULL;
    PVOID userVa = (PVOID)INJECTOR_CHANNEL_USER_VA;
    SIZE_T viewSize = INJECTOR_CHANNEL_TOTAL_SIZE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
#if DBG
        DbgPrint("[Driver] ChannelMapIntoProcess: wrong IRQL %u\n",
                 (unsigned)KeGetCurrentIrql());
#endif
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (Process == NULL)
        return STATUS_INVALID_PARAMETER;

    hSection = InjectorChannelGetSectionHandle();
    if (hSection == NULL) {
        InjectorDiagLog("[MapInto] exit: STATUS_NOT_READY (no section handle)\n");
        return STATUS_NOT_READY;
    }

    if (PsGetProcessExitStatus(Process) != STATUS_PENDING) {
        InjectorDiagLog("[MapInto] skip: process is exiting\n");
        return STATUS_PROCESS_IS_TERMINATING;
    }
    if (PsGetProcessPeb(Process) == NULL) {
        InjectorDiagLog("[MapInto] skip: no PEB\n");
        return STATUS_NOT_FOUND;
    }

    status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE,
                                   NULL, PROCESS_VM_OPERATION,
                                   *PsProcessType, KernelMode,
                                   &hProcess);
    if (!NT_SUCCESS(status)) {
        InjectorDiagLog("[MapInto] ObOpenObjectByPointer: status=0x%08X\n", status);
        return status;
    }

    if (PsGetProcessExitStatus(Process) != STATUS_PENDING) {
        ZwClose(hProcess);
        InjectorDiagLog("[MapInto] skip: process exiting at map time\n");
        return STATUS_PROCESS_IS_TERMINATING;
    }
    status = ZwMapViewOfSection(hSection, hProcess,
                                &userVa, 0, 0, NULL, &viewSize,
                                ViewUnmap, 0, PAGE_READWRITE);

    if (status == STATUS_CONFLICTING_ADDRESSES) {
        ZwClose(hProcess);
        InjectorDiagLog("[MapInto] pid=%lu already mapped (conflicting address)\n",
                      (unsigned long)(ULONG_PTR)PsGetProcessId(Process));
        /*
         * Reported as a conflict rather than success so the caller can tell
         * "another driver instance already owns the client VA" apart from
         * "this driver mapped it".
         */
        return STATUS_CONFLICTING_ADDRESSES;
    }
    if (!NT_SUCCESS(status)) {
        ZwClose(hProcess);
        InjectorDiagLog("[MapInto] ZwMapViewOfSection: status=0x%08X\n", status);
        return status;
    }

    if ((UINT_PTR)userVa != (UINT_PTR)INJECTOR_CHANNEL_USER_VA) {
        InjectorDiagLog("[MapInto] VA mismatch: got=%p expected=%p\n",
                      userVa, (PVOID)INJECTOR_CHANNEL_USER_VA);
        (void)ZwUnmapViewOfSection(hProcess, userVa);
        ZwClose(hProcess);
        return STATUS_CONFLICTING_ADDRESSES;
    }

    ZwClose(hProcess);

    InjectorDiagLog("[MapInto] mapped pid=%lu userVa=%p\n",
                  (unsigned long)(ULONG_PTR)PsGetProcessId(Process), userVa);
    return STATUS_SUCCESS;
}

NTSTATUS InjectorChannelMapExisting(VOID)
{
    NTSTATUS status;
    ULONG len = 0;
    ULONG used = 0;
    ULONG offset = 0;
    ULONG mappedCount = 0;
    ULONG conflictCount = 0;
    PINJECTOR_SYSTEM_PROCESS_INFORMATION spi = NULL;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
#if DBG
        DbgPrint("[Driver] ChannelMapExisting: wrong IRQL %u\n",
                 (unsigned)KeGetCurrentIrql());
#endif
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &len);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        InjectorDiagLog("[Existing] size query: status=0x%08X\n", status);
        return status;
    }

    len += 0x10000;
    spi = (PINJECTOR_SYSTEM_PROCESS_INFORMATION)ExAllocatePool2(
        POOL_FLAG_PAGED, len, INJECTOR_TAG_LOOKUP);
    if (spi == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    used = len;
    status = ZwQuerySystemInformation(SystemProcessInformation, spi, len, &used);
    if (!NT_SUCCESS(status)) {
        InjectorDiagLog("[Existing] query: status=0x%08X\n", status);
        ExFreePoolWithTag(spi, INJECTOR_TAG_LOOKUP);
        return status;
    }
    if (used > len)
        used = len;

    for (;;) {
        PINJECTOR_SYSTEM_PROCESS_INFORMATION cur;
        ULONG entrySize;

        if (offset + FIELD_OFFSET(INJECTOR_SYSTEM_PROCESS_INFORMATION, Threads) > used)
            break;

        cur = (PINJECTOR_SYSTEM_PROCESS_INFORMATION)((PUINT8)spi + offset);
        entrySize = (cur->NextEntryOffset != 0) ? cur->NextEntryOffset
                                                : (used - offset);
        if ((SIZE_T)entrySize <=
            (SIZE_T)FIELD_OFFSET(INJECTOR_SYSTEM_PROCESS_INFORMATION, Threads))
            break;

        if (cur->ImageName.Buffer != NULL && cur->ImageName.Length > 0) {
            CHAR img[16];
            ULONG chars = (ULONG)(cur->ImageName.Length / sizeof(WCHAR));
            ULONG i;

            if (chars > 14) chars = 14;
            RtlZeroMemory(img, sizeof(img));
            for (i = 0; i < chars; i++)
                img[i] = (CHAR)cur->ImageName.Buffer[i];

            if (InjectorImageNameMatch(img)) {
                PEPROCESS proc = NULL;
                NTSTATUS lookupStatus =
                    PsLookupProcessByProcessId(cur->UniqueProcessId, &proc);
                if (NT_SUCCESS(lookupStatus)) {
                    NTSTATUS mapStatus = InjectorChannelMapIntoProcess(proc);
                    InjectorDiagLog("[Existing] PID %lu map result=0x%08X\n",
                                  (unsigned long)(ULONG_PTR)cur->UniqueProcessId,
                                  mapStatus);
                    if (mapStatus == STATUS_CONFLICTING_ADDRESSES)
                        conflictCount++;
                    else if (NT_SUCCESS(mapStatus))
                        mappedCount++;
                    ObDereferenceObject(proc);
                } else {
                    InjectorDiagLog("[Existing] PID %lu lookup=0x%08X\n",
                                  (unsigned long)(ULONG_PTR)cur->UniqueProcessId,
                                  lookupStatus);
                }
            } else if (InjectorImageNamePrefixMatch(img, 4)) {

                InjectorDiagLog("[Existing] PID %lu candidate name='%s'\n",
                              (unsigned long)(ULONG_PTR)cur->UniqueProcessId,
                              img);
            }
        }

        if (cur->NextEntryOffset == 0 || cur->NextEntryOffset >= used - offset)
            break;
        offset += cur->NextEntryOffset;
    }

    ExFreePoolWithTag(spi, INJECTOR_TAG_LOOKUP);

    if (conflictCount != 0 && mappedCount == 0) {
        /*
         * Every candidate process already had the client VA mapped.  That is
         * what happens when a second copy of this driver is loaded while an
         * older copy is still resident: the older instance owns the VA and
         * keeps serving the client, so the rebuilt driver never runs.
         */
        InjectorDiagLog("[Existing] WARNING: %lu conflicts, 0 mappings - another "
                      "driver instance already owns VA 0x%llX. Reboot (or free the "
                      "old instance) before using a rebuilt driver.\n",
                      (unsigned long)conflictCount,
                      (unsigned long long)INJECTOR_CHANNEL_USER_VA);
    }

    return STATUS_SUCCESS;
}
