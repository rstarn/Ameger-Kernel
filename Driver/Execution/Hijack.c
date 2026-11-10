#include "Hijack.h"
#include "../Core/Process/Information.h"
#include <ntifs.h>
#include <ntimage.h>

extern VOID InjectorDiagLog(_In_ PCSTR Format, ...);

NTKERNELAPI PVOID PsGetThreadTeb(_In_ PETHREAD Thread);
NTKERNELAPI NTSTATUS PsGetContextThread(
    _In_ PETHREAD Thread, _Inout_ PCONTEXT ThreadContext,
    _In_ KPROCESSOR_MODE PreviousMode);
NTKERNELAPI NTSTATUS PsSetContextThread(
    _In_ PETHREAD Thread, _In_ PCONTEXT ThreadContext,
    _In_ KPROCESSOR_MODE PreviousMode);
NTKERNELAPI VOID NTAPI KeAlertThread(_In_ PKTHREAD Thread);

#ifndef CONTEXT_FULL
#define CONTEXT_FULL 0x10000B
#endif
#ifndef STATUS_INVALID_CONTEXT
#define STATUS_INVALID_CONTEXT ((NTSTATUS)0xC0000140L)
#endif
#ifndef STATUS_PARTIAL_COPY
#define STATUS_PARTIAL_COPY ((NTSTATUS)0x00000108L)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif

#define INJECTOR_THREAD_STATE_RUNNING      2
#define INJECTOR_THREAD_STATE_TERMINATED  4
#define INJECTOR_THREAD_STATE_WAITING     5

#define INJECTOR_WAIT_REASON_DELAY_EXECUTION  4
#define INJECTOR_WAIT_REASON_USER_REQUEST     6

#define INJECTOR_USER_MIN 0x10000ULL
#define INJECTOR_USER_MAX 0x00007FFFFFFF0000ULL

#define INJECTOR_MAX_CANDIDATES 32

typedef struct _INJECTOR_CANDIDATE {
    ULONG Tid;
    ULONG State;
    ULONG WaitReason;
    LONG Score;
} INJECTOR_CANDIDATE, *PINJECTOR_CANDIDATE;

static LONG
InjectorThreadScore(_In_ ULONG State, _In_ ULONG WaitReason)
{
    if (State == INJECTOR_THREAD_STATE_TERMINATED)
        return -1;

    if (State == INJECTOR_THREAD_STATE_WAITING) {
        switch (WaitReason) {
        case INJECTOR_WAIT_REASON_USER_REQUEST:
            return 5;
        case INJECTOR_WAIT_REASON_DELAY_EXECUTION:
            return 4;
        case 5:
        case 7:
            return -1;
        default:
            return 2;
        }
    }
    if (State == INJECTOR_THREAD_STATE_RUNNING)
        return 1;
    return -1;
}

static ULONG
InjectorGatherCandidates(_In_ PEPROCESS Target,
                       _Out_writes_(INJECTOR_MAX_CANDIDATES) PINJECTOR_CANDIDATE Out,
                       _Out_ PULONG OutCount, _Out_ PULONG OutTotal)
{
    PINJECTOR_THREAD_ENTRY entries = NULL;
    ULONG count = 0;
    ULONG i;
    ULONG n = 0;

    *OutCount = 0;
    *OutTotal = 0;

    if (!NT_SUCCESS(InjectorSnapshotThreads(
            (ULONG)(ULONG_PTR)PsGetProcessId(Target), &entries, &count)))
        return 0;

    *OutTotal = count;
    for (i = 0; i < count && n < INJECTOR_MAX_CANDIDATES; i++) {
        LONG score = InjectorThreadScore(entries[i].State, entries[i].WaitReason);

        if (score < 0)
            continue;

        Out[n].Tid = entries[i].ThreadId;
        Out[n].State = entries[i].State;
        Out[n].WaitReason = entries[i].WaitReason;
        Out[n].Score = score;
        n++;
    }
    InjectorFreeThreads(entries);

    for (i = 0; i < n; i++) {
        ULONG best = i;
        ULONG j;

        for (j = i + 1; j < n; j++) {
            if (Out[j].Score > Out[best].Score)
                best = j;
        }
        if (best != i) {
            INJECTOR_CANDIDATE tmp = Out[i];
            Out[i] = Out[best];
            Out[best] = tmp;
        }
    }

    *OutCount = n;
    return n;
}

static NTSTATUS
InjectorProbeUserModeContext(_In_ PEPROCESS Target, _In_ PETHREAD Thread,
                           _Out_ PCONTEXT OutCtx)
{
    HANDLE hProc = NULL;
    PVOID userBuf = NULL;
    SIZE_T sz = 0x1000;
    CONTEXT zero;
    KAPC_STATE stackApc;
    KAPC_STATE stackApc2;
    NTSTATUS status;

    RtlZeroMemory(OutCtx, sizeof(*OutCtx));
    RtlZeroMemory(&zero, sizeof(zero));
    zero.ContextFlags = CONTEXT_FULL;

    status = ObOpenObjectByPointer(Target, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_VM_OPERATION,
                                   *PsProcessType, KernelMode, &hProc);
    if (!NT_SUCCESS(status))
        return status;

    status = ZwAllocateVirtualMemory(hProc, &userBuf, 0, &sz,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        ZwClose(hProc);
        return status;
    }

    status = STATUS_SUCCESS;
    KeStackAttachProcess(Target, &stackApc);
    __try {
        RtlCopyMemory(userBuf, &zero, sizeof(zero));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = (NTSTATUS)GetExceptionCode();
    }
    KeUnstackDetachProcess(&stackApc);

    if (!NT_SUCCESS(status)) {
        PVOID freeBase = userBuf;
        SIZE_T freeSize = 0;

        (void)ZwFreeVirtualMemory(hProc, &freeBase, &freeSize, MEM_RELEASE);
        ZwClose(hProc);
        return status;
    }

    KeStackAttachProcess(Target, &stackApc);
    __try {
        status = PsGetContextThread(Thread, (PCONTEXT)userBuf, UserMode);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = (NTSTATUS)GetExceptionCode();
    }
    KeUnstackDetachProcess(&stackApc);

    if (NT_SUCCESS(status)) {
        KeStackAttachProcess(Target, &stackApc2);
        __try {
            RtlCopyMemory(OutCtx, userBuf, sizeof(*OutCtx));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
        }
        KeUnstackDetachProcess(&stackApc2);
    }

    {
        PVOID freeBase = userBuf;
        SIZE_T freeSize = 0;

        (void)ZwFreeVirtualMemory(hProc, &freeBase, &freeSize, MEM_RELEASE);
    }
    ZwClose(hProc);

    return status;
}

static NTSTATUS
InjectorProbeUserModeSetContext(_In_ PEPROCESS Target, _In_ PETHREAD Thread,
                              _In_ PCONTEXT Ctx)
{
    HANDLE hProc = NULL;
    PVOID userBuf = NULL;
    SIZE_T sz = 0x1000;
    KAPC_STATE stackApc;
    KAPC_STATE stackApc2;
    NTSTATUS status;

    status = ObOpenObjectByPointer(Target, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_VM_OPERATION,
                                   *PsProcessType, KernelMode, &hProc);
    if (!NT_SUCCESS(status))
        return status;

    status = ZwAllocateVirtualMemory(hProc, &userBuf, 0, &sz,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        ZwClose(hProc);
        return status;
    }

    status = STATUS_SUCCESS;
    KeStackAttachProcess(Target, &stackApc);
    __try {
        RtlCopyMemory(userBuf, Ctx, sizeof(*Ctx));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = (NTSTATUS)GetExceptionCode();
    }
    KeUnstackDetachProcess(&stackApc);

    if (NT_SUCCESS(status)) {
        KeStackAttachProcess(Target, &stackApc2);
        __try {
            status = PsSetContextThread(Thread, (PCONTEXT)userBuf, UserMode);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
        }
        KeUnstackDetachProcess(&stackApc2);
    }

    {
        PVOID freeBase = userBuf;
        SIZE_T freeSize = 0;

        (void)ZwFreeVirtualMemory(hProc, &freeBase, &freeSize, MEM_RELEASE);
    }
    ZwClose(hProc);

    return status;
}

static NTSTATUS
InjectorAttemptThread(_In_ PEPROCESS Target, _In_ PETHREAD Thread,
                    _In_ ULONG Tid, _In_ ULONG State, _In_ ULONG WaitReason,
                    _In_ UINT64 ExecutionVa, _In_ UINT64 RemoteBase,
                    _Out_ UINT64 *OutSlot)
{
    HANDLE hThread = NULL;
    CONTEXT ctx;
    UINT_PTR origRip;
    UINT_PTR origRsp;
    UINT_PTR returnSlotVa;
    NTSTATUS status;
    BOOLEAN viaUserMode = FALSE;

    *OutSlot = 0;

    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    status = ObOpenObjectByPointer(Thread, OBJ_KERNEL_HANDLE, NULL,
                                   THREAD_SUSPEND_RESUME |
                                   THREAD_GET_CONTEXT |
                                   THREAD_SET_CONTEXT,
                                   *PsThreadType, KernelMode, &hThread);
    InjectorDiagLog("[Hijack] tid=%lu state=%lu wait=%lu open status=0x%08X\n",
                  Tid, State, WaitReason, status);
    if (!NT_SUCCESS(status))
        return status;

    status = PsGetContextThread(Thread, &ctx, KernelMode);
    InjectorDiagLog("[Hijack] tid=%lu PsGetContextThread(km) status=0x%08X rip=0x%llX rsp=0x%llX\n",
                  Tid, status,
                  (unsigned long long)ctx.Rip,
                  (unsigned long long)ctx.Rsp);
    if (!NT_SUCCESS(status)) {
        NTSTATUS probe = InjectorProbeUserModeContext(Target, Thread, &ctx);

        InjectorDiagLog("[Hijack] tid=%lu probe(usermode) status=0x%08X rip=0x%llX rsp=0x%llX\n",
                      Tid, probe,
                      (unsigned long long)ctx.Rip,
                      (unsigned long long)ctx.Rsp);
        if (!NT_SUCCESS(probe)) {
            ZwClose(hThread);
            return probe;
        }
        ctx.ContextFlags = CONTEXT_FULL;
        viaUserMode = TRUE;
    }

    origRip = (UINT_PTR)ctx.Rip;
    origRsp = (UINT_PTR)ctx.Rsp;

    {
        BOOLEAN userRangeOk =
            (origRip >= INJECTOR_USER_MIN && origRip < INJECTOR_USER_MAX &&
             origRsp >= INJECTOR_USER_MIN && origRsp < INJECTOR_USER_MAX);

        InjectorDiagLog("[Hijack] tid=%lu user-range check rip=0x%llX rsp=0x%llX %s\n",
                      Tid, (unsigned long long)origRip,
                      (unsigned long long)origRsp,
                      userRangeOk ? "OK" : "REJECT");
        if (!userRangeOk) {
            ZwClose(hThread);
            return STATUS_INVALID_CONTEXT;
        }
    }

    status = STATUS_SUCCESS;
    returnSlotVa = 0;
    {
        HANDLE hProc = NULL;
        PVOID remoteBlock = NULL;
        SIZE_T remoteSz = 0x20000;
        NTSTATUS allocStatus;

        allocStatus = ObOpenObjectByPointer(Target, OBJ_KERNEL_HANDLE, NULL,
                                            PROCESS_VM_OPERATION,
                                            *PsProcessType, KernelMode,
                                            &hProc);
        if (!NT_SUCCESS(allocStatus)) {
            InjectorDiagLog("[Hijack] tid=%lu open target for stub failed: 0x%08X\n",
                          Tid, allocStatus);
            ZwClose(hThread);
            return allocStatus;
        }

        allocStatus = ZwAllocateVirtualMemory(hProc, &remoteBlock, 0, &remoteSz,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_EXECUTE_READWRITE);
        ZwClose(hProc);
        if (!NT_SUCCESS(allocStatus)) {
            InjectorDiagLog("[Hijack] tid=%lu stub alloc failed: 0x%08X\n",
                          Tid, allocStatus);
            ZwClose(hThread);
            return allocStatus;
        }

        {
            UINT64 stubAddr = (UINT64)(ULONG_PTR)remoteBlock + 0x10;
            UINT64 stackRsp = (UINT64)(ULONG_PTR)remoteBlock + 0x20000 - 0x28;
            UINT64 payloadRetAddr = stubAddr;
            PUINT8 p;
            KAPC_STATE stackApc;

            (void)remoteSz;
            KeStackAttachProcess(Target, &stackApc);
            __try {
                p = (PUINT8)remoteBlock + 0x10;
                *p++ = 0x48; *p++ = 0xBC; memcpy(p, &origRsp, sizeof(UINT64)); p += 8;
                *p++ = 0x48; *p++ = 0xB8; memcpy(p, &origRip, sizeof(UINT64)); p += 8;
                *p++ = 0xFF; *p++ = 0xE0;

                memcpy((PUINT8)remoteBlock + 0x20000 - 0x28, &payloadRetAddr,
                       sizeof(payloadRetAddr));
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                status = (NTSTATUS)GetExceptionCode();
            }
            KeUnstackDetachProcess(&stackApc);

            if (!NT_SUCCESS(status)) {
                InjectorDiagLog("[Hijack] tid=%lu stub write faulted: 0x%08X\n",
                              Tid, status);
                ZwClose(hThread);
                return status;
            }

            returnSlotVa = (UINT_PTR)stackRsp;
        }
    }
    InjectorDiagLog("[Hijack] tid=%lu trampoline stack at 0x%llX\n",
                  Tid, (unsigned long long)returnSlotVa);

    /*
     * Loader-compatible entry contract.  RCX carries the mapped image base
     * (the HMODULE a DllMain expects), RDX the reason and R8 the reserved
     * argument, so an image entry point can be called exactly the way the
     * Windows loader calls it (DLL_PROCESS_ATTACH).  For a plain exported
     * entry such as ManualEntry(HMODULE) the extra registers are ignored.
     */
    ctx.Rcx = (DWORD64)RemoteBase;
    ctx.Rdx = (DWORD64)INJECTOR_DLL_PROCESS_ATTACH;
    ctx.R8 = 0;
    ctx.Rip = (DWORD64)ExecutionVa;
    ctx.Rsp = (DWORD64)returnSlotVa;

    if (!viaUserMode) {
        status = PsSetContextThread(Thread, &ctx, KernelMode);
        InjectorDiagLog("[Hijack] tid=%lu PsSetContextThread(km) status=0x%08X\n",
                      Tid, status);
        if (!NT_SUCCESS(status)) {
            status = InjectorProbeUserModeSetContext(Target, Thread, &ctx);
            InjectorDiagLog("[Hijack] tid=%lu PsSetContextThread(usermode) status=0x%08X\n",
                          Tid, status);
        }
    } else {
        status = InjectorProbeUserModeSetContext(Target, Thread, &ctx);
        InjectorDiagLog("[Hijack] tid=%lu PsSetContextThread(usermode) status=0x%08X\n",
                      Tid, status);
    }
    if (!NT_SUCCESS(status)) {
        ZwClose(hThread);
        return status;
    }

    KeAlertThread((PKTHREAD)Thread);
    InjectorDiagLog("[Hijack] tid=%lu KeAlertThread issued\n", Tid);

    *OutSlot = (UINT64)returnSlotVa;
    ZwClose(hThread);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverKernelExecute(_Inout_ PINJECTOR_CHANNEL Ch,
                    _In_ PEPROCESS Target,
                    _In_ UINT64 ExecutionVa,
                    _In_ UINT64 RemoteBase,
                    _In_ UINT32 ImageSize)
{
    INJECTOR_CANDIDATE candidates[INJECTOR_MAX_CANDIDATES];
    ULONG total = 0;
    ULONG numCandidates = 0;
    ULONG i;
    UINT64 slot = 0;
    NTSTATUS status;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    if (Ch == NULL || Target == NULL || ImageSize == 0)
        return STATUS_INVALID_PARAMETER;

    if (ExecutionVa < RemoteBase || ExecutionVa >= RemoteBase + ImageSize) {
        InjectorDiagLog("[Hijack] FAILED status=0x%08X (ExecutionVa out of image)\n",
                      STATUS_INVALID_PARAMETER);
        InterlockedExchange(&Ch->HijackReserved, (LONG)STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }
    InjectorDiagLog("[Hijack] entry: pid=%lu ExecutionVa=0x%llX base=0x%llX size=0x%X\n",
                  (unsigned long)(ULONG_PTR)PsGetProcessId(Target),
                  (unsigned long long)ExecutionVa,
                  (unsigned long long)RemoteBase, ImageSize);

    numCandidates = InjectorGatherCandidates(Target, candidates,
                                           &numCandidates, &total);
    InjectorDiagLog("[Hijack] gathered %lu candidates (process threads=%lu)\n",
                  numCandidates, total);

    {
        ULONG preferredTid = (ULONG)Ch->Flags;
        LONG score10 = 10;

        if (preferredTid != 0) {
            BOOLEAN found = FALSE;
            ULONG k;

            InjectorDiagLog("[Hijack] preferred tid=%lu (client hint)\n",
                          preferredTid);
            for (k = 0; k < numCandidates; k++) {
                if (candidates[k].Tid == preferredTid) {
                    INJECTOR_CANDIDATE tmp = candidates[0];

                    candidates[0] = candidates[k];
                    candidates[k] = tmp;
                    found = TRUE;
                    break;
                }
            }
            if (!found) {
                if (numCandidates < INJECTOR_MAX_CANDIDATES) {

                    candidates[numCandidates].Tid = preferredTid;
                    candidates[numCandidates].State = INJECTOR_THREAD_STATE_WAITING;
                    candidates[numCandidates].WaitReason = INJECTOR_WAIT_REASON_USER_REQUEST;
                    candidates[numCandidates].Score = score10;
                    numCandidates++;
                    {
                        INJECTOR_CANDIDATE tmp = candidates[0];
                        candidates[0] = candidates[numCandidates - 1];
                        candidates[numCandidates - 1] = tmp;
                    }
                } else {

                    candidates[numCandidates - 1].Tid = preferredTid;
                    candidates[numCandidates - 1].State = INJECTOR_THREAD_STATE_WAITING;
                    candidates[numCandidates - 1].WaitReason = INJECTOR_WAIT_REASON_USER_REQUEST;
                    candidates[numCandidates - 1].Score = score10;
                    {
                        INJECTOR_CANDIDATE tmp = candidates[0];
                        candidates[0] = candidates[numCandidates - 1];
                        candidates[numCandidates - 1] = tmp;
                    }
                }
            }
        }
    }
    if (numCandidates == 0) {
        InjectorDiagLog("[Hijack] no eligible threads (total=%lu)\n", total);
        InjectorDiagLog("[Hijack] FAILED status=0x%08X\n", STATUS_NOT_FOUND);
        InterlockedExchange(&Ch->HijackReserved, (LONG)STATUS_NOT_FOUND);
        return STATUS_NOT_FOUND;
    }
    InjectorDiagLog("[Hijack] %lu candidates (process threads=%lu)\n",
                  numCandidates, total);

    for (i = 0; i < numCandidates; i++) {
        PETHREAD thread = NULL;

        if (!NT_SUCCESS(PsLookupThreadByThreadId(
                (HANDLE)(ULONG_PTR)candidates[i].Tid, &thread))) {
            InjectorDiagLog("[Hijack] tid=%lu lookup failed\n", candidates[i].Tid);
            lastStatus = STATUS_NOT_FOUND;
            continue;
        }

        if (PsGetThreadProcess(thread) != Target ||
            PsGetThreadTeb(thread) == NULL) {
            InjectorDiagLog("[Hijack] tid=%lu process/teb mismatch\n",
                          candidates[i].Tid);
            ObDereferenceObject(thread);
            continue;
        }

        status = InjectorAttemptThread(Target, thread,
                                     candidates[i].Tid,
                                     candidates[i].State,
                                     candidates[i].WaitReason,
                                     ExecutionVa, RemoteBase, &slot);
        if (NT_SUCCESS(status)) {
            (void)slot;
            InjectorDiagLog("[Hijack] resumed tid=%lu OK\n", candidates[i].Tid);
            InterlockedExchange(&Ch->HijackThreadId, (LONG)candidates[i].Tid);
            ObDereferenceObject(thread);
            InterlockedExchange(&Ch->HijackReserved, (LONG)STATUS_SUCCESS);
            return STATUS_SUCCESS;
        }

        lastStatus = status;
        InjectorDiagLog("[Hijack] tid=%lu attempt failed: 0x%08X\n",
                      candidates[i].Tid, status);
        ObDereferenceObject(thread);
    }

    InjectorDiagLog("[Hijack] FAILED all candidates, last=0x%08X\n", lastStatus);
    InterlockedExchange(&Ch->HijackReserved, (LONG)lastStatus);
    return lastStatus;
}
