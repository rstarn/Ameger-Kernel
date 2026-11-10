#pragma once

#include <ntifs.h>

NTSTATUS AmegerTlsSetup(_In_ PEPROCESS Target,
                        _In_ PVOID RemoteBase,
                        _In_ UINT32 PayloadSize,
                        _Out_ LONG *OutSlot,
                        _Out_ LONG *OutSeeded);

NTSTATUS AmegerTlsGetInstall(_In_ PEPROCESS Target,
                             _Out_ PVOID *OutBlock, _Out_ LONG *OutSlot);

NTSTATUS AmegerTlsNotifyArm(VOID);
VOID     AmegerTlsNotifyDisarm(VOID);
VOID     AmegerTlsNotifyTick(VOID);

NTSTATUS AmegerTlsInstallForThread(_In_ PETHREAD Thread);

VOID AmegerTlsPollProcess(_In_ PEPROCESS Target);

BOOLEAN AmegerTlsIsActive(VOID);

UINT32 AmegerTlsGetTargetPid(VOID);

VOID AmegerTlsUnregisterNotify(VOID);
