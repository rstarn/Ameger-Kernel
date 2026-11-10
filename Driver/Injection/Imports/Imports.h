#pragma once

#include <ntifs.h>

NTSTATUS AmegerResolveImports(_In_ PEPROCESS Target,
                              _In_ UINT8 *Image,
                              _In_ UINT32 ImageSize);

NTSTATUS AmegerFindImageExport(_In_ UINT8 *Image,
                               _In_ UINT32 ImageSize,
                               _In_ const char *Symbol,
                               _Out_ ULONG *OutRva);
