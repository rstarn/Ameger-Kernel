#pragma once

#include <ntifs.h>

typedef struct _AMEGER_POLL_STATE {
    KTIMER          Timer;
    KDPC            Dpc;
    WORK_QUEUE_ITEM WorkItem;
    volatile LONG   Armed;
    volatile LONG   WorkPending;
} AMEGER_POLL_STATE, *PAMEGER_POLL_STATE;

PAMEGER_POLL_STATE AmegerPollGetState(VOID);

NTSTATUS AmegerPollInitialize(VOID);
VOID     AmegerPollShutdown(VOID);
