#pragma once

#include <ntifs.h>

NTSTATUS InjectorResolveImports(_In_ PEPROCESS Target,
                              _In_ UINT8 *Image,
                              _In_ UINT32 ImageSize,
                              _In_ BOOLEAN AllowDependencyLoad);

NTSTATUS InjectorFindImageExport(_In_ UINT8 *Image,
                               _In_ UINT32 ImageSize,
                               _In_ const char *Symbol,
                               _Out_ ULONG *OutRva);

/* Modules the driver had to pull into the target because the target had not
   loaded them itself.  Reported to the client through the channel. */
ULONG  InjectorGetDependencyCount(VOID);
VOID   InjectorResetDependencyCount(VOID);
