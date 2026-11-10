#pragma once

#include <ntifs.h>
#include <ntimage.h>

typedef struct _INJECTOR_EXPORTS {
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
} INJECTOR_EXPORTS, *PINJECTOR_EXPORTS;

NTSTATUS InjectorExportsInitialize(PINJECTOR_EXPORTS Out);
VOID     InjectorExportsDestroy(PINJECTOR_EXPORTS Exports);
PVOID    InjectorResolveExport(PINJECTOR_EXPORTS Exports,
                             PCSTR ModuleName,
                             PCSTR FunctionName);
