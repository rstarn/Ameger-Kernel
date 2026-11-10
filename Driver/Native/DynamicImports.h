#pragma once

#include <ntifs.h>
#include <ntimage.h>

typedef struct _AMEGER_EXPORTS {
    PVOID    NtoskrnlBase;
    ULONG    NtoskrnlSize;
    PVOID    ObRegisterCallbacks;
    PVOID    ObUnRegisterCallbacks;
    PVOID   *PsProcessType;
    PVOID   *PsThreadType;
    PVOID    StorportBase;
    PVOID    AcpiBase;
    PVOID    TcpipBase;
    PVOID    NdisBase;
} AMEGER_EXPORTS, *PAMEGER_EXPORTS;

NTSTATUS AmegerExportsInitialize(PAMEGER_EXPORTS Out);
VOID     AmegerExportsDestroy(PAMEGER_EXPORTS Exports);
PVOID    AmegerResolveExport(PAMEGER_EXPORTS Exports,
                             PCSTR ModuleName,
                             PCSTR FunctionName);
