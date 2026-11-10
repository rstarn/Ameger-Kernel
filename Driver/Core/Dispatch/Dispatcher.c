#include "Dispatcher.h"
#include "../Communication/Channel/Channel.h"
#include "../../NT/Definitions.h"
#include "../../Injection/DLL/Payload.h"
#include "../../TLS/TLS.h"
#include "../../Stealth/ObCallback.h"

extern VOID InjectorDiagLog(_In_ PCSTR Format, ...);

#define INJECTOR_CMD_TIMER_PERIOD_MS  100

static PINJECTOR_CMD_STATE g_CmdState = NULL;
static volatile LONG     g_Init = 0;

static VOID InjectorCommandDpc(_In_ KDPC *Dpc, _In_opt_ PVOID Ctx,
                             _In_opt_ PVOID A1, _In_opt_ PVOID A2);
static VOID InjectorCommandWorker(_In_ PVOID Ctx);

PINJECTOR_CMD_STATE
InjectorCommandGetState(VOID)
{
    return g_CmdState;
}

NTSTATUS
InjectorCommandInitialize(VOID)
{
    LARGE_INTEGER due;

    if (InterlockedCompareExchange(&g_Init, 0, 0) != 0)
        return STATUS_ALREADY_REGISTERED;

    g_CmdState = (PINJECTOR_CMD_STATE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(INJECTOR_CMD_STATE), INJECTOR_TAG_CHANNEL);
    if (g_CmdState == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_CmdState, sizeof(INJECTOR_CMD_STATE));

    KeInitializeTimerEx(&g_CmdState->Timer, NotificationTimer);
    KeInitializeDpc(&g_CmdState->Dpc, InjectorCommandDpc, NULL);
    ExInitializeWorkItem(&g_CmdState->WorkItem, InjectorCommandWorker, NULL);

    due.QuadPart = -(LONGLONG)INJECTOR_CMD_TIMER_PERIOD_MS * 10000LL;
    KeSetTimerEx(&g_CmdState->Timer, due, INJECTOR_CMD_TIMER_PERIOD_MS, &g_CmdState->Dpc);
    InterlockedExchange(&g_CmdState->Armed, 1);

    InterlockedExchange(&g_Init, 1);
    return STATUS_SUCCESS;
}

VOID
InjectorCommandShutdown(VOID)
{
    PINJECTOR_CMD_STATE st = g_CmdState;

    if (InterlockedCompareExchange(&g_Init, 0, 0) == 0)
        return;

    if (st != NULL) {
        KeCancelTimer(&st->Timer);
        KeFlushQueuedDpcs();
        InterlockedExchange(&st->Armed, 0);
    }

    InterlockedExchange(&g_Init, 0);

    if (st != NULL) {
        for (int i = 0; i < 200; i++) {
            if (InterlockedCompareExchange(&st->WorkPending, 0, 0) == 0)
                break;
            KeStallExecutionProcessor(10000);
        }
    }

    if (st != NULL) {
        ExFreePoolWithTag(st, INJECTOR_TAG_CHANNEL);
        g_CmdState = NULL;
    }
}

static VOID
InjectorCommandDpc(_In_ KDPC *Dpc, _In_opt_ PVOID Ctx,
                 _In_opt_ PVOID A1, _In_opt_ PVOID A2)
{
    PINJECTOR_CMD_STATE st = InjectorCommandGetState();

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(A1);
    UNREFERENCED_PARAMETER(A2);

    if (st == NULL)
        return;
    if (InterlockedCompareExchange(&st->Armed, 0, 0) == 0)
        return;

    if (InterlockedCompareExchange(&st->WorkPending, 1, 0) == 0) {
        ExQueueWorkItem(&st->WorkItem, CriticalWorkQueue);
    }
}

static VOID
InjectorCommandWorker(_In_ PVOID Ctx)
{
    PINJECTOR_CMD_STATE st = InjectorCommandGetState();
    PINJECTOR_CHANNEL ch;
    PUINT8 buf;
    UINT32 bufSize;
    NTSTATUS status = STATUS_SUCCESS;
    LONG head, tail, cmd;
    UINT32 avail, received, want, chunk, ringIdx;

    UNREFERENCED_PARAMETER(Ctx);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
#if DBG
        DbgPrint("[Driver] CommandWorker: wrong IRQL %u\n",
                 (unsigned)KeGetCurrentIrql());
#endif
        if (st != NULL) InterlockedExchange(&st->WorkPending, 0);
        return;
    }

    ch = InjectorChannelGet();
    buf = InjectorChannelGetPayloadBuffer();
    bufSize = InjectorChannelGetPayloadBufferSize();

    if (st == NULL || ch == NULL || buf == NULL) {
        if (st != NULL) InterlockedExchange(&st->WorkPending, 0);
        return;
    }

    if (InterlockedCompareExchange(&g_Init, 0, 0) == 0) {
        InterlockedExchange(&st->WorkPending, 0);
        return;
    }

    if (InterlockedCompareExchange(&ch->Cmd, 0, 0) != INJECTOR_CMD_NONE) {
        InjectorDiagLog("[Cmd] worker entry: irql=%u cmd=%ld done=%ld head=%ld tail=%ld\n",
                      (unsigned)KeGetCurrentIrql(),
                      (long)InterlockedCompareExchange(&ch->Cmd, 0, 0),
                      (long)InterlockedCompareExchange(&ch->Done, 0, 0),
                      (long)InterlockedCompareExchange(&ch->Head, 0, 0),
                      (long)InterlockedCompareExchange(&ch->Tail, 0, 0));
    }

    if (InterlockedCompareExchange(&ch->Done, 0, 0) != 0) {
        InterlockedExchange(&st->WorkPending, 0);
        return;
    }

    head = InterlockedCompareExchange(&ch->Head, 0, 0);
    tail = InterlockedCompareExchange(&ch->Tail, 0, 0);
    avail = (UINT32)(head - tail);
    received = ch->PayloadReceived;
    want = ch->PayloadSize;
    if (want > bufSize) want = bufSize;

    while (avail > 0 && received < want) {
        ringIdx = (UINT32)tail % INJECTOR_CHANNEL_RING_SIZE;
        chunk = INJECTOR_CHANNEL_RING_SIZE - ringIdx;
        if (chunk > avail) chunk = avail;
        if (chunk > want - received) chunk = want - received;
        RtlCopyMemory(buf + received, ch->Ring + ringIdx, chunk);
        received += chunk;
        tail += (LONG)chunk;
        avail -= chunk;
    }

    ch->PayloadReceived = received;
    InterlockedExchange(&ch->Tail, tail);

    cmd = InterlockedCompareExchange(&ch->Cmd, 0, 0);
    if (cmd == INJECTOR_CMD_NONE ||
        !((cmd == INJECTOR_CMD_EXEC) ||
          (cmd == INJECTOR_CMD_PROTECT_PID) ||
          (received == ch->PayloadSize && received > 0))) {
        InterlockedExchange(&st->WorkPending, 0);
        return;
    }

    if (cmd == INJECTOR_CMD_PROTECT_PID) {
        status = InjectorObCallbackProtectPid(ch->ProtectedPid);
        InterlockedExchange(&ch->ObCallbackStatus, (LONG)status);
        InterlockedExchange64((volatile LONG64 *)&ch->GadgetVa,
                              (LONG64)InjectorObCallbackGetGadgetVa());
        goto worker_finish;
    }

    if (cmd == INJECTOR_CMD_EXEC) {

        if (InterlockedCompareExchange(&ch->TlsSlot, 0, 0) !=
            INJECTOR_TLS_SLOT_INVALID) {
            NTSTATUS armStatus = InjectorTlsNotifyArm();
            if (!NT_SUCCESS(armStatus))
                InjectorDiagLog("[Cmd] TLS notify arm failed: 0x%08X\n",
                              armStatus);
        }

        status = DriverKernelExec(ch);

        if (!NT_SUCCESS(status))
            InjectorTlsNotifyDisarm();
    } else if (ch->PayloadSize == 0 || ch->PayloadSize > bufSize) {
        status = STATUS_INVALID_PARAMETER;
    } else {
        if (cmd == INJECTOR_CMD_VALIDATE) {
            UINT32 psz = ch->PayloadSize;
            InjectorDiagLog("[Cmd] VALIDATE: size=%u head=%ld tail=%ld received=%u first8=%02X%02X%02X%02X%02X%02X%02X%02X\n",
                          psz, (long)head, (long)tail, (unsigned)received,
                          (unsigned)(psz > 0 ? buf[0] : 0),
                          (unsigned)(psz > 1 ? buf[1] : 0),
                          (unsigned)(psz > 2 ? buf[2] : 0),
                          (unsigned)(psz > 3 ? buf[3] : 0),
                          (unsigned)(psz > 4 ? buf[4] : 0),
                          (unsigned)(psz > 5 ? buf[5] : 0),
                          (unsigned)(psz > 6 ? buf[6] : 0),
                          (unsigned)(psz > 7 ? buf[7] : 0));
        }
        status = DriverKernelValidate(ch, buf, ch->PayloadSize);
        if (NT_SUCCESS(status) && cmd == INJECTOR_CMD_MAP) {
            status = DriverKernelMap(ch, buf, ch->PayloadSize);
        }
    }

worker_finish:
    ch->CmdStatus = (LONG)status;
    InterlockedExchange(&ch->Cmd, INJECTOR_CMD_NONE);
    InterlockedExchange(&ch->Done, 1);
    InterlockedExchange(&st->WorkPending, 0);

    InjectorDiagLog("[Cmd] worker exit: cmd=%ld status=0x%08X\n", cmd, status);

#if DBG
    DbgPrint("[Driver] worker cmd=%ld status=0x%08X\n", cmd, status);
#endif
}
