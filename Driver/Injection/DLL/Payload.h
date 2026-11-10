#pragma once

#include <ntifs.h>
#include "../KernelMapping/KernelMapping.h"
#include "../../Core/Communication/Channel/Channel.h"

NTSTATUS DriverKernelValidate(_Inout_ PINJECTOR_CHANNEL Ch,
                              _In_reads_bytes_(Size) const UINT8 *Buf,
                              _In_ UINT32 Size);

NTSTATUS DriverKernelMap(_Inout_ PINJECTOR_CHANNEL Ch,
                         _In_reads_bytes_(Size) const UINT8 *Buf,
                         _In_ UINT32 Size);

NTSTATUS DriverKernelExec(_Inout_ PINJECTOR_CHANNEL Ch);

/*
 * Map an image into the target and resolve its imports.  Shared by the
 * payload and by the dependency loader.
 */
NTSTATUS InjectorMapImageIntoTarget(_In_ PEPROCESS Target,
                                    _In_reads_bytes_(Size) const UINT8 *Buf,
                                    _In_ SIZE_T Size,
                                    _Out_ PVOID *OutBase,
                                    _Out_ PVOID *OutSysView,
                                    _Out_ PHANDLE OutProcess,
                                    _Out_ PINJECTOR_PE_INFO OutInfo,
                                    _In_ BOOLEAN AllowDependencyLoad);
