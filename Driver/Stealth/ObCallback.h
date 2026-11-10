#pragma once

#include <ntifs.h>
#include "../Native/DynamicImports.h"

NTSTATUS AmegerObCallbackInitialize(PAMEGER_EXPORTS Exports);
VOID     AmegerObCallbackShutdown(VOID);
NTSTATUS AmegerObCallbackProtectPid(UINT32 Pid);
UINT64   AmegerObCallbackGetGadgetVa(VOID);
