#pragma once

#include <ntifs.h>
#include "../../Core/Communication/Channel/Channel.h"

NTSTATUS DriverKernelValidate(_Inout_ PAMEGER_CHANNEL Ch,
                              _In_reads_bytes_(Size) const UINT8 *Buf,
                              _In_ UINT32 Size);

NTSTATUS DriverKernelMap(_Inout_ PAMEGER_CHANNEL Ch,
                         _In_reads_bytes_(Size) const UINT8 *Buf,
                         _In_ UINT32 Size);

NTSTATUS DriverKernelExec(_Inout_ PAMEGER_CHANNEL Ch);
