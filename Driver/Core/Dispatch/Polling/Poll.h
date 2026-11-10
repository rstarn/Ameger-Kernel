#pragma once

#include <ntifs.h>

typedef struct _INJECTOR_POLL_STATE {
    KTIMER          Timer;
    KDPC            Dpc;
    WORK_QUEUE_ITEM WorkItem;
    volatile LONG   Armed;
    volatile LONG   WorkPending;
} INJECTOR_POLL_STATE, *PINJECTOR_POLL_STATE;

PINJECTOR_POLL_STATE InjectorPollGetState(VOID);

NTSTATUS InjectorPollInitialize(VOID);
VOID     InjectorPollShutdown(VOID);
