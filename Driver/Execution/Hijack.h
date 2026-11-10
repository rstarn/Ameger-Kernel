#pragma once

#include <ntifs.h>
#include "../Core/Communication/Channel/Channel.h"

NTSTATUS DriverKernelExecute(_Inout_ PINJECTOR_CHANNEL Ch,
                             _In_ PEPROCESS Target,
                             _In_ UINT64 ExecutionVa,
                             _In_ UINT64 RemoteBase,
                             _In_ UINT32 ImageSize);
