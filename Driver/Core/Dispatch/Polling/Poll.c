#include "Poll.h"
#include "../../Communication/Mapping/Mapping.h"
#include "../../../NT/Definitions.h"
#include "../../../TLS/TLS.h"

extern VOID InjectorDiagLog(_In_ PCSTR Format, ...);

#define INJECTOR_POLL_PERIOD_MS  1000

static PINJECTOR_POLL_STATE g_PollState = NULL;
static volatile LONG      g_PollInit = 0;

static VOID InjectorPollDpc(_In_ KDPC *Dpc, _In_opt_ PVOID Ctx,
                          _In_opt_ PVOID A1, _In_opt_ PVOID A2);
static VOID InjectorPollWorker(_In_ PVOID Ctx);

PINJECTOR_POLL_STATE
InjectorPollGetState(VOID)
{
    return g_PollState;
}

NTSTATUS
InjectorPollInitialize(VOID)
{
    LARGE_INTEGER due;

    if (InterlockedCompareExchange(&g_PollInit, 0, 0) != 0)
        return STATUS_ALREADY_REGISTERED;

    g_PollState = (PINJECTOR_POLL_STATE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(INJECTOR_POLL_STATE), INJECTOR_TAG_CHANNEL);
    if (g_PollState == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_PollState, sizeof(INJECTOR_POLL_STATE));

    KeInitializeTimerEx(&g_PollState->Timer, NotificationTimer);
    KeInitializeDpc(&g_PollState->Dpc, InjectorPollDpc, NULL);
    ExInitializeWorkItem(&g_PollState->WorkItem, InjectorPollWorker, NULL);

    due.QuadPart = -(LONGLONG)INJECTOR_POLL_PERIOD_MS * 10000LL;
    KeSetTimerEx(&g_PollState->Timer, due, INJECTOR_POLL_PERIOD_MS, &g_PollState->Dpc);
    InterlockedExchange(&g_PollState->Armed, 1);

    InterlockedExchange(&g_PollInit, 1);
    return STATUS_SUCCESS;
}

VOID
InjectorPollShutdown(VOID)
{
    PINJECTOR_POLL_STATE st = g_PollState;

    if (InterlockedCompareExchange(&g_PollInit, 0, 0) == 0)
        return;

    if (st != NULL) {
        KeCancelTimer(&st->Timer);
        KeFlushQueuedDpcs();
        InterlockedExchange(&st->Armed, 0);
    }

    InterlockedExchange(&g_PollInit, 0);

    if (st != NULL) {
        for (int i = 0; i < 200; i++) {
            if (InterlockedCompareExchange(&st->WorkPending, 0, 0) == 0)
                break;
            KeStallExecutionProcessor(10000);
        }
        ExFreePoolWithTag(st, INJECTOR_TAG_CHANNEL);
        g_PollState = NULL;
    }
}

static VOID
InjectorPollDpc(_In_ KDPC *Dpc, _In_opt_ PVOID Ctx,
              _In_opt_ PVOID A1, _In_opt_ PVOID A2)
{
    PINJECTOR_POLL_STATE st = InjectorPollGetState();

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
InjectorPollWorker(_In_ PVOID Ctx)
{
    PINJECTOR_POLL_STATE st = InjectorPollGetState();

    UNREFERENCED_PARAMETER(Ctx);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
#if DBG
        DbgPrint("[Driver] PollWorker: wrong IRQL %u\n",
                 (unsigned)KeGetCurrentIrql());
#endif
        if (st != NULL) InterlockedExchange(&st->WorkPending, 0);
        return;
    }

    if (st == NULL) {
        return;
    }

    InjectorDiagLog("[Poll] worker entry: irql=%u init=%ld pending=%ld\n",
                  (unsigned)KeGetCurrentIrql(),
                  (long)InterlockedCompareExchange(&g_PollInit, 0, 0),
                  (long)InterlockedCompareExchange(&st->WorkPending, 0, 0));

    if (InterlockedCompareExchange(&g_PollInit, 0, 0) == 0) {
        InterlockedExchange(&st->WorkPending, 0);
        return;
    }

    {
        NTSTATUS mapStatus = InjectorChannelMapExisting();
        InjectorDiagLog("[Poll] MapExisting returned 0x%08X\n", mapStatus);
    }

    InjectorTlsNotifyTick();
    if (InjectorTlsIsActive()) {
        UINT32 pid = InjectorTlsGetTargetPid();
        if (pid != 0) {
            PEPROCESS proc = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc))) {
                InjectorTlsPollProcess(proc);
                ObDereferenceObject(proc);
            }
        }
    }

    InterlockedExchange(&st->WorkPending, 0);
}
