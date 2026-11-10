#pragma once

#include <ntifs.h>

typedef struct _INJECTOR_CMD_STATE {
    KTIMER          Timer;
    KDPC            Dpc;
    WORK_QUEUE_ITEM WorkItem;
    volatile LONG   Armed;
    volatile LONG   WorkPending;
} INJECTOR_CMD_STATE, *PINJECTOR_CMD_STATE;

PINJECTOR_CMD_STATE InjectorCommandGetState(VOID);

NTSTATUS InjectorCommandInitialize(VOID);
VOID     InjectorCommandShutdown(VOID);
