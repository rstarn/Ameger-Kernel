#pragma once

#include <ntifs.h>

typedef struct _AMEGER_CMD_STATE {
    KTIMER          Timer;
    KDPC            Dpc;
    WORK_QUEUE_ITEM WorkItem;
    volatile LONG   Armed;
    volatile LONG   WorkPending;
} AMEGER_CMD_STATE, *PAMEGER_CMD_STATE;

PAMEGER_CMD_STATE AmegerCommandGetState(VOID);

NTSTATUS AmegerCommandInitialize(VOID);
VOID     AmegerCommandShutdown(VOID);
