#pragma once

#include <ntifs.h>
#include "../Core/Communication/Channel/Channel.h"

/* Reason codes the Windows loader passes to DllMain / TLS callbacks. */
#define INJECTOR_DLL_PROCESS_ATTACH  1
#define INJECTOR_DLL_THREAD_ATTACH   2

NTSTATUS DriverKernelExecute(_Inout_ PINJECTOR_CHANNEL Ch,
                             _In_ PEPROCESS Target,
                             _In_ UINT64 ExecutionVa,
                             _In_ UINT64 RemoteBase,
                             _In_ UINT32 ImageSize);
