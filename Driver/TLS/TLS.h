#pragma once

#include <ntifs.h>

NTSTATUS InjectorTlsSetup(_In_ PEPROCESS Target,
                        _In_ PVOID RemoteBase,
                        _In_ UINT32 PayloadSize,
                        _Out_ LONG *OutSlot,
                        _Out_ LONG *OutSeeded);

NTSTATUS InjectorTlsGetInstall(_In_ PEPROCESS Target,
                             _Out_ PVOID *OutBlock, _Out_ LONG *OutSlot);

NTSTATUS InjectorTlsNotifyArm(VOID);
VOID     InjectorTlsNotifyDisarm(VOID);
VOID     InjectorTlsNotifyTick(VOID);

NTSTATUS InjectorTlsInstallForThread(_In_ PETHREAD Thread);

VOID InjectorTlsPollProcess(_In_ PEPROCESS Target);

BOOLEAN InjectorTlsIsActive(VOID);

UINT32 InjectorTlsGetTargetPid(VOID);

VOID InjectorTlsUnregisterNotify(VOID);
