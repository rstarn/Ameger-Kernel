#include "ObCallback.h"
#include "../Core/Communication/Channel/Channel.h"
#include <ntimage.h>
#include <intrin.h>

#ifndef OB_FLT_REGISTRATION_VERSION
#define OB_FLT_REGISTRATION_VERSION 0x0100
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ        0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE       0x0020
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION   0x0008
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD  0x0002
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE     0x0040
#endif
#ifndef STATUS_NOT_READY
#define STATUS_NOT_READY       ((NTSTATUS)0xC00000A3L)
#endif

#ifndef STATUS_FLT_INSTANCE_ALTITUDE_COLLISION
#define STATUS_FLT_INSTANCE_ALTITUDE_COLLISION  ((NTSTATUS)0xC01C000Au)
#endif
#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION            ((NTSTATUS)0xC0000035u)
#endif

extern VOID InjectorDiagLog(_In_ PCSTR Format, ...);

static PINJECTOR_EXPORTS g_Exports = NULL;
static PVOID           g_ProcRegHandle = NULL;
static PVOID           g_ThreadRegHandle = NULL;
static volatile LONG   g_ProtectedPid = 0;
static volatile UINT64 g_GadgetVa = 0;

#define INJECTOR_CR0_WP 0x00010000ULL

typedef struct _EXEC_SECTION {
    UINT8  *Base;
    ULONGLONG Va;
    SIZE_T Size;
} EXEC_SECTION, *PEXEC_SECTION;

static ULONG
EnumerExecutableSections(_In_ PVOID ImageBase,
                         _Out_writes_to_(MaxOut, MaxOut) PEXEC_SECTION Out,
                         _In_ ULONG MaxOut)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)ImageBase;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sec;
    ULONG i;
    ULONG count = 0;

    if (ImageBase == NULL || MaxOut == 0) return 0;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew <= 0) return 0;

    nt = (IMAGE_NT_HEADERS64 *)((UINT8 *)ImageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections && count < MaxOut; i++) {
        if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        if (sec[i].Misc.VirtualSize == 0) continue;
        Out[count].Base = (UINT8 *)ImageBase + sec[i].VirtualAddress;
        Out[count].Va   = sec[i].VirtualAddress;
        Out[count].Size = sec[i].Misc.VirtualSize;
        count++;
    }
    return count;
}

static PVOID
ResolveVerifyFunction(_In_ PINJECTOR_EXPORTS Exports)
{

    static const UINT8 kSitePattern[6] = { 0xBA, 0x20, 0x00, 0x00, 0x00, 0xE8 };
    EXEC_SECTION execs[16];
    ULONG execCount;
    ULONG i;
    PUINT8 text = (PUINT8)Exports->ObRegisterCallbacks;
    const SIZE_T kScanBytes = 4096;
    PUINT8 candidates[8];
    UINT64 counts[8];
    ULONG candidateCount = 0;

    if (Exports == NULL || Exports->NtoskrnlBase == NULL ||
        Exports->ObRegisterCallbacks == NULL)
        return NULL;

    execCount = EnumerExecutableSections(Exports->NtoskrnlBase, execs, ARRAYSIZE(execs));
    if (execCount == 0) {
        InjectorDiagLog("[ObInit] no executable sections in ntoskrnl - gadget path\n");
        return NULL;
    }

    for (i = 0; i + 10 <= kScanBytes; i++) {
        PUINT8 target;
        INT32 rel;
        UINT64 inExec;
        ULONG j;

        if (RtlCompareMemory(text + i, kSitePattern, 6) != 6)
            continue;

        rel = *(const INT32 *)(text + i + 6);
        target = (PUINT8)((ULONG_PTR)&text[i + 10] + rel);

        inExec = 0;
        for (j = 0; j < execCount; j++) {
            if (target >= execs[j].Base &&
                target < execs[j].Base + execs[j].Size) {
                inExec = 1;
                break;
            }
        }
        if (inExec == 0) continue;

        for (j = 0; j < candidateCount; j++) {
            if (candidates[j] == target) { counts[j]++; break; }
        }
        if (j == candidateCount) {
            if (candidateCount >= ARRAYSIZE(candidates)) {
                InjectorDiagLog("[ObInit] verify anchor overflow - gadget path\n");
                return NULL;
            }
            candidates[candidateCount] = target;
            counts[candidateCount] = 1;
            candidateCount++;
        }
    }

    for (i = 0; i < candidateCount; i++) {
        InjectorDiagLog("[ObInit] verify anchor candidate=%p hits=%llu\n",
                      candidates[i], (unsigned long long)counts[i]);
    }

    if (candidateCount != 1) {
        InjectorDiagLog("[ObInit] anchor did not resolve to exactly one function (%u) - gadget path\n",
                      candidateCount);
        return NULL;
    }
    return candidates[0];
}

static VOID
InjectorWpOff(VOID)
{
    __writecr0((unsigned __int64)__readcr0() & ~INJECTOR_CR0_WP);
}

static VOID
InjectorWpOn(VOID)
{
    __writecr0((unsigned __int64)__readcr0() | INJECTOR_CR0_WP);
}

static BOOLEAN
ApplyVerifyPatch(_In_ PVOID Target, _Out_writes_(9) UINT8 Saved[9])
{
    static const UINT8 patch[8] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90 };

    if (Target == NULL) return FALSE;
    RtlCopyMemory(Saved, Target, 8);
    InjectorWpOff();
    RtlCopyMemory(Target, patch, 8);
    InjectorWpOn();
    return RtlCompareMemory(Target, patch, 8) == 8;
}

static BOOLEAN
RestoreVerifyPatch(_In_ PVOID Target, _In_reads_(9) const UINT8 Saved[9])
{
    InjectorWpOff();
    RtlCopyMemory(Target, Saved, 8);
    InjectorWpOn();
    return RtlCompareMemory(Target, Saved, 8) == 8;
}

static UINT64 ScanForJmpRcx(_In_reads_bytes_(Size) const UINT8 *Text, SIZE_T Size, _Out_opt_ ULONG *Accepted)
{
    SIZE_T i;
    ULONG accepted = 0;
    if (Accepted != NULL) *Accepted = 0;
    if (Text == NULL || Size < 4) return 0;

    for (i = 2; i + 1 < Size; i++) {
        UINT8 prev, prev2;

        if (Text[i] != 0xFF || Text[i + 1] != 0xE1) continue;

        prev  = Text[i - 1];
        prev2 = Text[i - 2];

        if (prev >= 0x40 && prev <= 0x4F) continue;
        if (prev == 0x66 || prev == 0x67 || prev == 0x0F) continue;
        if (prev == 0xF0 || prev == 0xF2 || prev == 0xF3) continue;
        if (prev == 0x2E || prev == 0x36 || prev == 0x3E) continue;
        if (prev == 0x26 || prev == 0x64 || prev == 0x65) continue;

        if (prev == 0xFF && (prev2 & 0x38) == 0x10) continue;

        accepted++;
        if (Accepted != NULL) *Accepted = accepted;
        return (UINT64)(ULONG_PTR)&Text[i];
    }
    if (Accepted != NULL) *Accepted = accepted;
    return 0;
}

static UINT64 FindGadgetInModule(PVOID ModuleBase, _In_opt_ PCSTR ModuleName)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sec;
    ULONG i;

    if (ModuleBase == NULL) {
        InjectorDiagLog("[Gadget] %s base NULL\n", ModuleName ? ModuleName : "?");
        return 0;
    }
    dos = (IMAGE_DOS_HEADER *)ModuleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000) return 0;

    nt = (IMAGE_NT_HEADERS64 *)((UINT8 *)ModuleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            UINT8 *text = (UINT8 *)ModuleBase + sec[i].VirtualAddress;
            SIZE_T textSize = sec[i].Misc.VirtualSize;
            ULONG accepted = 0;
            UINT64 found;
            if (textSize == 0) textSize = sec[i].SizeOfRawData;
            if (textSize < 8) continue;
            found = ScanForJmpRcx(text, textSize, &accepted);
            InjectorDiagLog("[Gadget] %s sec=%u rva=0x%X size=0x%X accepted=%u found=0x%llX\n",
                          ModuleName ? ModuleName : "?", (unsigned)i,
                          (unsigned)sec[i].VirtualAddress, (unsigned)textSize,
                          (unsigned)accepted, (unsigned long long)found);
            if (found) return found;
        }
    }
    InjectorDiagLog("[Gadget] %s no FF E1 in executable sections\n", ModuleName ? ModuleName : "?");
    return 0;
}

static ACCESS_MASK StripProcess(ACCESS_MASK Desired)
{
    return Desired & ~(PROCESS_VM_READ | PROCESS_VM_WRITE |
                       PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
                       PROCESS_DUP_HANDLE);
}

static ACCESS_MASK StripThread(ACCESS_MASK Desired)
{
    return Desired & ~(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                       THREAD_SUSPEND_RESUME | THREAD_SET_INFORMATION);
}

static OB_PREOP_CALLBACK_STATUS
RealPreCallback(_In_ PVOID RegistrationContext,
                _In_ POB_PRE_OPERATION_INFORMATION OpInfo)
{
    LONG protectedPid;
    ACCESS_MASK *desired = NULL;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OpInfo == NULL || OpInfo->Object == NULL) return OB_PREOP_SUCCESS;
    if (OpInfo->KernelHandle) return OB_PREOP_SUCCESS;

    protectedPid = InterlockedCompareExchange(&g_ProtectedPid, 0, 0);
    if (protectedPid == 0) return OB_PREOP_SUCCESS;

    if (g_Exports != NULL && g_Exports->PsProcessType != NULL &&
        OpInfo->ObjectType == *g_Exports->PsProcessType) {
        PEPROCESS target = (PEPROCESS)OpInfo->Object;
        if ((LONG)(ULONG_PTR)PsGetProcessId(target) != protectedPid)
            return OB_PREOP_SUCCESS;
        if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
            desired = &OpInfo->Parameters->CreateHandleInformation.DesiredAccess;
        else if (OpInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            desired = &OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
        if (desired) *desired = StripProcess(*desired);
        return OB_PREOP_SUCCESS;
    }

    if (g_Exports != NULL && g_Exports->PsThreadType != NULL &&
        OpInfo->ObjectType == *g_Exports->PsThreadType) {
        PETHREAD target = (PETHREAD)OpInfo->Object;
        PEPROCESS owner = IoThreadToProcess(target);
        if (owner == NULL) return OB_PREOP_SUCCESS;
        if ((LONG)(ULONG_PTR)PsGetProcessId(owner) != protectedPid)
            return OB_PREOP_SUCCESS;
        if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
            desired = &OpInfo->Parameters->CreateHandleInformation.DesiredAccess;
        else if (OpInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            desired = &OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
        if (desired) *desired = StripThread(*desired);
        return OB_PREOP_SUCCESS;
    }

    return OB_PREOP_SUCCESS;
}

static NTSTATUS RegisterOne(PVOID ObjectType, UINT64 GadgetVa,
                            PCSTR Altitude, PVOID *OutHandle)
{
    OB_CALLBACK_REGISTRATION reg;
    OB_OPERATION_REGISTRATION ops;
    UNICODE_STRING alt;
    WCHAR altW[32];
    SIZE_T i = 0;
    NTSTATUS status;

    while (Altitude[i] && i < 31) { altW[i] = (WCHAR)Altitude[i]; i++; }
    altW[i] = 0;
    RtlInitUnicodeString(&alt, altW);

    RtlZeroMemory(&reg, sizeof(reg));
    RtlZeroMemory(&ops, sizeof(ops));

    ops.ObjectType    = ObjectType;
    ops.Operations    = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops.PreOperation  = (POB_PRE_OPERATION_CALLBACK)(ULONG_PTR)GadgetVa;
    ops.PostOperation = NULL;

    reg.Version                    = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    reg.RegistrationContext        = (PVOID)RealPreCallback;
    reg.OperationRegistration      = &ops;
    reg.Altitude                   = alt;

    status = ObRegisterCallbacks(&reg, OutHandle);
    return status;
}

typedef struct _ALTITUDE_PAIR {
    const char *Proc;
    const char *Thread;
} ALTITUDE_PAIR;

static const ALTITUDE_PAIR kAltitudeLadder[] = {

    { "399990", "399991" },

    { "399900", "399901" },

    { "350000", "350001" },

    { "240000", "240001" },

    { "321900", "321901" },

    { "321000", "321001" },
};

static NTSTATUS RegisterBoth(PINJECTOR_EXPORTS Exports, UINT64 GadgetVa)
{
    UINT32 i;
    NTSTATUS status;

    for (i = 0; i < ARRAYSIZE(kAltitudeLadder); i++) {
        g_ProcRegHandle = NULL;
        g_ThreadRegHandle = NULL;

        status = RegisterOne(*Exports->PsProcessType, GadgetVa,
                             kAltitudeLadder[i].Proc, &g_ProcRegHandle);
        InjectorDiagLog("[ObInit] RegisterOne(process,%s) status=0x%08X\n",
                      kAltitudeLadder[i].Proc, (unsigned)status);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION ||
                status == STATUS_OBJECT_NAME_COLLISION) {
                continue;
            }
            return status;
        }

        status = RegisterOne(*Exports->PsThreadType, GadgetVa,
                             kAltitudeLadder[i].Thread, &g_ThreadRegHandle);
        InjectorDiagLog("[ObInit] RegisterOne(thread,%s) status=0x%08X\n",
                      kAltitudeLadder[i].Thread, (unsigned)status);
        if (NT_SUCCESS(status)) {
            InjectorDiagLog("[ObInit] altitudes: %s / %s\n",
                          kAltitudeLadder[i].Proc, kAltitudeLadder[i].Thread);
            return STATUS_SUCCESS;
        }

        ObUnRegisterCallbacks(g_ProcRegHandle);
        g_ProcRegHandle = NULL;

        if (status != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION &&
            status != STATUS_OBJECT_NAME_COLLISION) {
            return status;
        }
    }

    return STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;
}

typedef struct _OB_GADGET_CANDIDATE {
    PVOID Base;
    PCSTR Name;
} OB_GADGET_CANDIDATE;

NTSTATUS InjectorObCallbackInitialize(PINJECTOR_EXPORTS Exports)
{
    NTSTATUS status;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;
    NTSTATUS registerFailure = STATUS_NOT_FOUND;
    BOOLEAN sawRegisterFailure = FALSE;
    OB_GADGET_CANDIDATE candidates[4];
    ULONG i;
    BOOLEAN registered = FALSE;
    PVOID verifyTarget = NULL;
    BOOLEAN verifyPatched = FALSE;
    UINT8 savedBytes[9];

    if (Exports == NULL) return STATUS_INVALID_PARAMETER;
    if (g_ProcRegHandle != NULL) return STATUS_ALREADY_REGISTERED;
    g_Exports = Exports;
    RtlZeroMemory(savedBytes, sizeof(savedBytes));

    verifyTarget = ResolveVerifyFunction(Exports);
    if (verifyTarget == NULL) {
        InjectorDiagLog("[ObInit] verify target unavailable - gadget path\n");
    } else {
        verifyPatched = ApplyVerifyPatch(verifyTarget, savedBytes);
        InjectorDiagLog("[ObInit] verify patch target=%p ok=%u\n", verifyTarget, (unsigned)verifyPatched);
    }

    if (verifyPatched) {
        g_GadgetVa = (UINT64)(ULONG_PTR)RealPreCallback;
        status = RegisterBoth(Exports, g_GadgetVa);
        if (NT_SUCCESS(status)) {
            registered = TRUE;
            lastStatus = STATUS_SUCCESS;
        } else {
            sawRegisterFailure = TRUE;
            registerFailure = status;
            lastStatus = status;
        }
    } else {
        candidates[0].Base = Exports->TcpipBase;    candidates[0].Name = "tcpip.sys";
        candidates[1].Base = Exports->NdisBase;     candidates[1].Name = "ndis.sys";
        candidates[2].Base = Exports->StorportBase; candidates[2].Name = "storport.sys";
        candidates[3].Base = Exports->AcpiBase;     candidates[3].Name = "acpi.sys";

        InjectorDiagLog("[ObInit] tcpip=%p ndis=%p storport=%p acpi=%p\n",
                      Exports->TcpipBase, Exports->NdisBase,
                      Exports->StorportBase, Exports->AcpiBase);

        for (i = 0; i < ARRAYSIZE(candidates); i++) {
            UINT64 gadgetVa;

            if (candidates[i].Base == NULL) {
                InjectorDiagLog("[ObInit] %s base NULL - skipping\n", candidates[i].Name);
                continue;
            }

            gadgetVa = FindGadgetInModule(candidates[i].Base, candidates[i].Name);
            InjectorDiagLog("[ObInit] gadget from %s: 0x%llX\n",
                          candidates[i].Name, (unsigned long long)gadgetVa);
            if (gadgetVa == 0) {
                lastStatus = STATUS_NOT_FOUND;
                continue;
            }

            g_GadgetVa = gadgetVa;
            status = RegisterBoth(Exports, gadgetVa);
            if (NT_SUCCESS(status)) {
                registered = TRUE;
                lastStatus = status;
                break;
            }

            InjectorDiagLog("[ObInit] register with %s gadget failed: 0x%08X - trying next module\n",
                          candidates[i].Name, (unsigned)status);
            g_GadgetVa = 0;
            sawRegisterFailure = TRUE;
            registerFailure = status;
            lastStatus = status;

            if (status == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION ||
                status == STATUS_OBJECT_NAME_COLLISION) {
                break;
            }
        }
    }

    if (verifyPatched) {
        BOOLEAN restored = RestoreVerifyPatch(verifyTarget, savedBytes);
        InjectorDiagLog("[ObInit] verify restore ok=%u\n", (unsigned)restored);
        if (!restored) {
            InjectorDiagLog("[ObInit] FATAL: verify restore mismatch at %p - bugchecking\n",
                          verifyTarget);
            KeBugCheckEx(0x109, (ULONG_PTR)verifyTarget, 0, 0, 'AGMR');
        }
    }

    if (!registered) {
        NTSTATUS report = sawRegisterFailure ? registerFailure : lastStatus;
        InjectorDiagLog("[ObInit] FAILED: no usable callback module (last status 0x%08X)\n",
                      (unsigned)report);
#if DBG
        DbgPrint("[Driver] no usable callback module (last 0x%08X)\n", report);
#endif
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "Driver: ObCallback init failed 0x%08X\n", (unsigned)report);
        g_GadgetVa = 0;
        {
            PINJECTOR_CHANNEL ch = InjectorChannelGet();
            if (ch != NULL) {
                InterlockedExchange(&ch->ObInitStatus, (LONG)report);
            }
        }
        return report;
    }

    InjectorDiagLog("[ObInit] OK gadget=0x%llX verifyPatched=%u procHandle=%p threadHandle=%p\n",
                  (unsigned long long)g_GadgetVa, (unsigned)verifyPatched,
                  g_ProcRegHandle, g_ThreadRegHandle);
    {
        PINJECTOR_CHANNEL ch = InjectorChannelGet();
        if (ch != NULL) {
            InterlockedExchange(&ch->ObInitStatus, 0);
        }
    }
    return STATUS_SUCCESS;
}

VOID InjectorObCallbackShutdown(VOID)
{
    if (g_ThreadRegHandle) { ObUnRegisterCallbacks(g_ThreadRegHandle); g_ThreadRegHandle = NULL; }
    if (g_ProcRegHandle)   { ObUnRegisterCallbacks(g_ProcRegHandle);   g_ProcRegHandle   = NULL; }
    InterlockedExchange(&g_ProtectedPid, 0);
    InterlockedExchange64((volatile LONG64 *)&g_GadgetVa, 0);
    g_Exports = NULL;
}

NTSTATUS InjectorObCallbackProtectPid(UINT32 Pid)
{

    if (g_ProcRegHandle == NULL || g_ThreadRegHandle == NULL) {
        PINJECTOR_EXPORTS exportsHint = g_Exports;
        if (exportsHint != NULL) {
            NTSTATUS retry = InjectorObCallbackInitialize(exportsHint);
            if (NT_SUCCESS(retry) ||
                (g_ProcRegHandle != NULL && g_ThreadRegHandle != NULL)) {
                InterlockedExchange(&g_ProtectedPid, (LONG)Pid);
                return STATUS_SUCCESS;
            }
            {
                PINJECTOR_CHANNEL ch = InjectorChannelGet();
                if (ch != NULL) {
                    InterlockedExchange(&ch->ObInitStatus, (LONG)retry);
                }
            }
            return retry;
        }
        return STATUS_NOT_READY;
    }
    InterlockedExchange(&g_ProtectedPid, (LONG)Pid);
    return STATUS_SUCCESS;
}

UINT64 InjectorObCallbackGetGadgetVa(VOID)
{
    return (UINT64)InterlockedCompareExchange64((volatile LONG64 *)&g_GadgetVa, 0, 0);
}
