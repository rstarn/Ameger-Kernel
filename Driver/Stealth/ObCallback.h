#pragma once

#include <ntifs.h>
#include "../Native/DynamicImports.h"

NTSTATUS InjectorObCallbackInitialize(PINJECTOR_EXPORTS Exports);
VOID     InjectorObCallbackShutdown(VOID);
NTSTATUS InjectorObCallbackProtectPid(UINT32 Pid);
UINT64   InjectorObCallbackGetGadgetVa(VOID);
