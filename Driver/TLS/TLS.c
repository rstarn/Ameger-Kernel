#include "TLS.h"
#include "../NT/Definitions.h"
#include "../Core/Process/Information.h"
#include "../Core/Communication/Channel/Channel.h"
#include <ntimage.h>

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _In_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize);

NTKERNELAPI PVOID PsGetThreadTeb(_In_ PETHREAD Thread);
NTKERNELAPI NTSTATUS PsGetContextThread(
    _In_ PETHREAD Thread, _Inout_ PCONTEXT ThreadContext,
    _In_ KPROCESSOR_MODE Mode);
NTKERNELAPI NTSTATUS PsSetContextThread(
    _In_ PETHREAD Thread, _In_ PCONTEXT ThreadContext,
    _In_ KPROCESSOR_MODE Mode);

NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect);

extern VOID AmegerDiagLog(_In_ PCSTR Format, ...);

#ifndef STATUS_PROCESS_IS_TERMINATING
#define STATUS_PROCESS_IS_TERMINATING ((NTSTATUS)0xC000010AL)
#endif

#ifndef STATUS_INVALID_CONTEXT
#define STATUS_INVALID_CONTEXT ((NTSTATUS)0xC0000140L)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif

#ifndef CONTEXT_FULL
#define CONTEXT_FULL 0x10000B
#endif

#define AMEGER_TLS_MAX_VECTORS          1024
#define AMEGER_TLS_MAX_SLOT             1024
#define AMEGER_TLS_MAX_TEMPLATE         0x10000
#define AMEGER_TLS_VECTOR_HEADER        0x10
#define AMEGER_TLS_TEB_VECTOR_OFFSET    0x58
#define AMEGER_TLS_NOTIFY_100NS         (3ULL * 1000ULL * 10000ULL)
#define AMEGER_TLS_CODE_SIZE            128

#define AMEGER_USER_MIN 0x10000ULL
#define AMEGER_USER_MAX 0x00007FFFFFFF0000ULL

typedef struct _AMEGER_TLS_VECTOR {
    PVOID Va;
    ULONG Length;
} AMEGER_TLS_VECTOR, *PAMEGER_TLS_VECTOR;

static volatile LONG g_TlsInit = 0;
static HANDLE        g_TlsProcId = NULL;
static LONG          g_TlsSlot = AMEGER_TLS_SLOT_INVALID;
static PUINT8        g_TlsTemplate = NULL;
static UINT32        g_TlsTemplateSize = 0;
static UINT32        g_TlsSizeOfZeroFill = 0;

static volatile LONG   g_TlsNotifyArmed = 0;
static volatile UINT64 g_TlsNotifyDeadline = 0;

static PVOID            g_TlsBlock = NULL;

static NTSTATUS
TlsRead(_In_ PEPROCESS Proc,
        _In_ PVOID Remote,
        _Out_writes_bytes_(Size) PVOID Local,
        _In_ SIZE_T Size)
{
    NTSTATUS status;
    SIZE_T done = 0;

    if (Size == 0)
        return STATUS_SUCCESS;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    status = MmCopyVirtualMemory(Proc, Remote,
                                 PsGetCurrentProcess(), Local,
                                 Size, KernelMode, &done);
    if (NT_SUCCESS(status) && done != Size)
        return STATUS_PARTIAL_COPY;
    return status;
}

static NTSTATUS
TlsWrite(_In_ PEPROCESS Proc,
         _In_ PVOID Remote,
         _In_reads_bytes_(Size) const VOID *Local,
         _In_ SIZE_T Size)
{
    NTSTATUS status;
    SIZE_T done = 0;

    if (Size == 0)
        return STATUS_SUCCESS;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    status = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)Local,
                                 Proc, Remote,
                                 Size, KernelMode, &done);
    if (NT_SUCCESS(status) && done != Size)
        return STATUS_PARTIAL_COPY;
    return status;
}

static NTSTATUS
TlsAllocRemote(_In_ PEPROCESS Proc, _In_ SIZE_T Size,
               _In_ ULONG Protect, _Out_ PVOID *Out)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    PVOID base = NULL;
    SIZE_T size = Size;

    *Out = NULL;
    if (Size == 0)
        return STATUS_INVALID_PARAMETER;

    status = ObOpenObjectByPointer(Proc, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_VM_OPERATION,
                                   *PsProcessType, KernelMode, &hProcess);
    if (!NT_SUCCESS(status))
        return status;

    status = ZwAllocateVirtualMemory(hProcess, &base, 0, &size,
                                     MEM_COMMIT | MEM_RESERVE,
                                     Protect);
    ZwClose(hProcess);

    if (NT_SUCCESS(status) && base != NULL)
        *Out = base;
    return status;
}

static VOID
TlsFreeRemote(_In_ PEPROCESS Proc, _In_ PVOID Base)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    PVOID base = Base;
    SIZE_T size = 0;

    if (Base == NULL)
        return;

    status = ObOpenObjectByPointer(Proc, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_VM_OPERATION,
                                   *PsProcessType, KernelMode, &hProcess);
    if (!NT_SUCCESS(status))
        return;

    (void)ZwFreeVirtualMemory(hProcess, &base, &size, MEM_RELEASE);
    ZwClose(hProcess);
}

static VOID
TlsProtectRemote(_In_ PEPROCESS Proc, _In_ PVOID Base,
                 _In_ SIZE_T Size, _In_ ULONG Protect)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    PVOID base = Base;
    SIZE_T size = Size;
    ULONG oldProt = 0;

    status = ObOpenObjectByPointer(Proc, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_VM_OPERATION,
                                   *PsProcessType, KernelMode, &hProcess);
    if (!NT_SUCCESS(status))
        return;

    (void)ZwProtectVirtualMemory(hProcess, &base, &size, Protect, &oldProt);
    ZwClose(hProcess);
}

static NTSTATUS
TlsReadVector(_In_ PEPROCESS Proc, _In_ PETHREAD Thread,
              _Out_ PVOID *OutVector, _Out_ ULONG *OutLength)
{
    NTSTATUS status;
    PVOID tebVa;
    PVOID vector = NULL;
    ULONG length = 0;

    *OutVector = NULL;
    *OutLength = 0;

    tebVa = PsGetThreadTeb(Thread);
    if (tebVa == NULL)
        return STATUS_NOT_FOUND;

    status = TlsRead(Proc,
                     (PUINT8)tebVa + AMEGER_TLS_TEB_VECTOR_OFFSET,
                     &vector, sizeof(vector));
    if (!NT_SUCCESS(status))
        return status;
    if (vector == NULL || vector == (PVOID)((PUINT8)tebVa + AMEGER_TLS_TEB_VECTOR_OFFSET))
        return STATUS_NOT_FOUND;

    status = TlsRead(Proc,
                     (PUINT8)vector - AMEGER_TLS_VECTOR_HEADER,
                     &length, sizeof(length));
    if (!NT_SUCCESS(status))
        return status;
    if (length == 0 || length > AMEGER_TLS_MAX_SLOT)
        return STATUS_NOT_FOUND;

    *OutVector = vector;
    *OutLength = length;
    return STATUS_SUCCESS;
}

static NTSTATUS
TlsCollectVectors(_In_ PEPROCESS Proc,
                  _Outptr_result_buffer_(*OutCount) PAMEGER_TLS_VECTOR *OutVectors,
                  _Out_ PULONG OutCount)
{
    PAMEGER_THREAD_ENTRY entries = NULL;
    PAMEGER_TLS_VECTOR vectors = NULL;
    ULONG count = 0;
    ULONG found = 0;
    ULONG i;

    *OutVectors = NULL;
    *OutCount = 0;

    if (!NT_SUCCESS(AmegerSnapshotThreads(
            (ULONG)(ULONG_PTR)PsGetProcessId(Proc), &entries, &count)))
        return STATUS_NOT_SUPPORTED;
    if (count == 0) {
        AmegerFreeThreads(entries);
        return STATUS_NOT_SUPPORTED;
    }
    if (count > AMEGER_TLS_MAX_VECTORS)
        count = AMEGER_TLS_MAX_VECTORS;

    vectors = (PAMEGER_TLS_VECTOR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (SIZE_T)count * sizeof(AMEGER_TLS_VECTOR),
        AMEGER_TAG_LOOKUP);
    if (vectors == NULL) {
        AmegerFreeThreads(entries);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (i = 0; i < count; i++) {
        PETHREAD thread = NULL;
        PVOID vector = NULL;
        ULONG length = 0;

        if (!NT_SUCCESS(PsLookupThreadByThreadId(
                (HANDLE)(ULONG_PTR)entries[i].ThreadId, &thread)))
            continue;

        if (NT_SUCCESS(TlsReadVector(Proc, thread, &vector, &length))) {
            vectors[found].Va = vector;
            vectors[found].Length = length;
            found++;
        }

        ObDereferenceObject(thread);
    }

    AmegerFreeThreads(entries);

    if (found == 0) {
        ExFreePoolWithTag(vectors, AMEGER_TAG_LOOKUP);
        return STATUS_NOT_SUPPORTED;
    }

    *OutVectors = vectors;
    *OutCount = found;
    return STATUS_SUCCESS;
}

static NTSTATUS
TlsChooseSlot(_In_ PEPROCESS Proc,
              _In_reads_(Count) const AMEGER_TLS_VECTOR *Vectors,
              _In_ ULONG Count, _Out_ ULONG *OutSlot)
{
    ULONG minLength = AMEGER_TLS_MAX_SLOT;
    ULONG maxSlot;
    ULONG slot;
    ULONG i;

    *OutSlot = 0;

    for (i = 0; i < Count; i++) {
        if (Vectors[i].Length < minLength)
            minLength = Vectors[i].Length;
    }

    maxSlot = minLength - 1;

    for (slot = maxSlot + 1; slot-- > 0; ) {
        BOOLEAN available = TRUE;

        for (i = 0; i < Count; i++) {
            PVOID entry = NULL;
            NTSTATUS status;

            status = TlsRead(Proc,
                             (PUINT8)Vectors[i].Va + slot * sizeof(PVOID),
                             &entry, sizeof(entry));
            if (!NT_SUCCESS(status) || entry != NULL) {
                available = FALSE;
                break;
            }
        }

        if (!available)
            continue;

        *OutSlot = slot;
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS
TlsAllocateBlock(_In_ PEPROCESS Proc,
                 _In_reads_bytes_opt_(TemplateSize) const UINT8 *Template,
                 _In_ UINT32 TemplateSize, _In_ UINT32 SizeOfZeroFill,
                 _Out_ PVOID *OutBlock)
{
    NTSTATUS status;
    PVOID base = NULL;
    PVOID block;
    UINT64 zero = 0;
    SIZE_T dataSize;

    *OutBlock = NULL;

    dataSize = (SIZE_T)TemplateSize + (SIZE_T)SizeOfZeroFill;
    if (dataSize == 0)
        dataSize = 1;
    if (dataSize > AMEGER_TLS_MAX_TEMPLATE)
        return STATUS_INVALID_IMAGE_FORMAT;

    status = TlsAllocRemote(Proc, dataSize + AMEGER_TLS_VECTOR_HEADER,
                            PAGE_READWRITE, &base);
    if (!NT_SUCCESS(status))
        return status;

    block = (PVOID)(((ULONG_PTR)base + 8 + 15) & ~(ULONG_PTR)15);

    status = TlsWrite(Proc, (PUINT8)block - sizeof(UINT64),
                      &zero, sizeof(zero));
    if (!NT_SUCCESS(status)) {
        TlsFreeRemote(Proc, base);
        return status;
    }

    if (TemplateSize > 0 && Template != NULL) {
        status = TlsWrite(Proc, block, Template, TemplateSize);
        if (!NT_SUCCESS(status)) {
            TlsFreeRemote(Proc, base);
            return status;
        }
    }

    *OutBlock = block;
    return STATUS_SUCCESS;
}

static NTSTATUS
TlsInstallOne(_In_ PEPROCESS Proc, _In_ PETHREAD Thread, _In_ LONG Slot,
              _In_reads_bytes_opt_(TemplateSize) const UINT8 *Template,
              _In_ UINT32 TemplateSize, _In_ UINT32 SizeOfZeroFill)
{
    NTSTATUS status;
    PVOID vector = NULL;
    ULONG length = 0;
    PVOID existing = NULL;
    PVOID block = NULL;
    SIZE_T indexOffset;

    if (Slot < 0 || Slot >= AMEGER_TLS_MAX_SLOT)
        return STATUS_INVALID_PARAMETER;

    status = TlsReadVector(Proc, Thread, &vector, &length);
    if (!NT_SUCCESS(status))
        return status;

    if ((ULONG)Slot >= length)
        return STATUS_NOT_SUPPORTED;

    indexOffset = (SIZE_T)Slot * sizeof(PVOID);
    status = TlsRead(Proc, (PUINT8)vector + indexOffset,
                     &existing, sizeof(existing));
    if (!NT_SUCCESS(status))
        return status;
    if (existing != NULL)
        return STATUS_SUCCESS;

    status = TlsAllocateBlock(Proc, Template, TemplateSize,
                              SizeOfZeroFill, &block);
    if (!NT_SUCCESS(status))
        return status;

    status = TlsWrite(Proc, (PUINT8)vector + indexOffset,
                      &block, sizeof(block));
    if (!NT_SUCCESS(status)) {
        TlsFreeRemote(Proc, (PVOID)((ULONG_PTR)block - AMEGER_TLS_VECTOR_HEADER));
        return status;
    }

    return STATUS_SUCCESS;
}

static VOID
TlsEmit(_Inout_ PUINT8 Code, _Inout_ SIZE_T *Pos,
        _In_reads_(Count) const UINT8 *Bytes, _In_ SIZE_T Count)
{
    RtlCopyMemory(Code + *Pos, Bytes, Count);
    *Pos += Count;
}

static VOID
TlsEmitImm64(_Inout_ PUINT8 Code, _Inout_ SIZE_T *Pos, _In_ UINT64 Value)
{
    RtlCopyMemory(Code + *Pos, &Value, sizeof(Value));
    *Pos += sizeof(Value);
}

static VOID
TlsEmitImm32(_Inout_ PUINT8 Code, _Inout_ SIZE_T *Pos, _In_ UINT32 Value)
{
    RtlCopyMemory(Code + *Pos, &Value, sizeof(Value));
    *Pos += sizeof(Value);
}

static NTSTATUS
TlsBuildTrampoline(_In_ PEPROCESS Proc, _In_ PETHREAD Thread, _In_ LONG Slot,
                   _In_reads_bytes_opt_(TemplateSize) const UINT8 *Template,
                   _In_ UINT32 TemplateSize, _In_ UINT32 SizeOfZeroFill)
{
    static const UINT8 prologue[] = {
        0x50, 0x53, 0x51, 0x52,
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0, 0, 0,
        0x65, 0x48, 0x8B, 0x14, 0x25, 0x30, 0, 0, 0,
        0x48, 0x83, 0xC2, 0x58,
        0x48, 0x39, 0xD0
    };
    NTSTATUS status;
    CONTEXT ctx;
    PVOID blockVa = NULL;
    PVOID codeVa = NULL;
    PVOID vector = NULL;
    ULONG length = 0;
    UINT8 code[AMEGER_TLS_CODE_SIZE];
    SIZE_T n = 0;
    SIZE_T jSelf;
    SIZE_T jNull;
    SIZE_T jLength;
    SIZE_T skipTarget;
    UINT64 blockBits;
    UINT64 ripBits;
    UINT32 slotCompare;
    UINT32 slotDisp;

    if (Slot < 0 || Slot >= AMEGER_TLS_MAX_SLOT)
        return STATUS_INVALID_PARAMETER;

    status = TlsReadVector(Proc, Thread, &vector, &length);
    if (NT_SUCCESS(status))
        return TlsInstallOne(Proc, Thread, Slot, Template,
                             TemplateSize, SizeOfZeroFill);
    if (status != STATUS_NOT_FOUND)
        return status;

    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    status = PsGetContextThread(Thread, &ctx, KernelMode);
    if (!NT_SUCCESS(status))
        return status;
    if ((UINT_PTR)ctx.Rip < AMEGER_USER_MIN ||
        (UINT_PTR)ctx.Rip >= AMEGER_USER_MAX)
        return STATUS_INVALID_CONTEXT;

    status = TlsAllocateBlock(Proc, Template, TemplateSize,
                              SizeOfZeroFill, &blockVa);
    if (!NT_SUCCESS(status))
        return status;

    status = TlsAllocRemote(Proc, 0x1000, PAGE_EXECUTE_READWRITE, &codeVa);
    if (!NT_SUCCESS(status)) {
        TlsFreeRemote(Proc, (PVOID)((ULONG_PTR)blockVa - AMEGER_TLS_VECTOR_HEADER));
        return status;
    }

    TlsEmit(code, &n, prologue, sizeof(prologue));

    jSelf = n;
    code[n++] = 0x74;
    code[n++] = 0;

    code[n++] = 0x48;
    code[n++] = 0x85;
    code[n++] = 0xC0;

    jNull = n;
    code[n++] = 0x74;
    code[n++] = 0;

    {
        static const UINT8 loadLength[] = { 0x8B, 0x58, 0xF0 };
        TlsEmit(code, &n, loadLength, sizeof(loadLength));
    }

    code[n++] = 0x81;
    code[n++] = 0xFB;
    slotCompare = (UINT32)Slot + 1;
    TlsEmitImm32(code, &n, slotCompare);

    jLength = n;
    code[n++] = 0x72;
    code[n++] = 0;

    code[n++] = 0x48;
    code[n++] = 0xBB;
    blockBits = (UINT64)(ULONG_PTR)blockVa;
    TlsEmitImm64(code, &n, blockBits);

    code[n++] = 0x48;
    code[n++] = 0x89;
    code[n++] = 0x98;
    slotDisp = (UINT32)Slot * sizeof(PVOID);
    TlsEmitImm32(code, &n, slotDisp);

    skipTarget = n;
    code[jSelf + 1] = (UINT8)(skipTarget - (jSelf + 1));
    code[jNull + 1] = (UINT8)(skipTarget - (jNull + 1));
    code[jLength + 1] = (UINT8)(skipTarget - (jLength + 1));

    {
        static const UINT8 epilogue[] = { 0x5A, 0x59, 0x5B, 0x58 };
        TlsEmit(code, &n, epilogue, sizeof(epilogue));
    }

    code[n++] = 0x48;
    code[n++] = 0xB8;
    ripBits = (UINT64)(UINT_PTR)ctx.Rip;
    TlsEmitImm64(code, &n, ripBits);

    code[n++] = 0xFF;
    code[n++] = 0xE0;

    status = TlsWrite(Proc, codeVa, code, n);
    if (!NT_SUCCESS(status)) {
        TlsFreeRemote(Proc, codeVa);
        TlsFreeRemote(Proc, (PVOID)((ULONG_PTR)blockVa - AMEGER_TLS_VECTOR_HEADER));
        return status;
    }

    TlsProtectRemote(Proc, codeVa, 0x1000, PAGE_EXECUTE_READ);

    ctx.Rip = (DWORD64)(ULONG_PTR)codeVa;
    status = PsSetContextThread(Thread, &ctx, KernelMode);
    if (!NT_SUCCESS(status)) {

        AmegerDiagLog("[Tls] SetContextThread tid=%lu failed: 0x%08X\n",
                      (unsigned long)(ULONG_PTR)PsGetThreadId(Thread),
                      status);
        return status;
    }

    AmegerDiagLog("[Tls] trampoline tid=%lu slot=%ld block=%p\n",
                  (unsigned long)(ULONG_PTR)PsGetThreadId(Thread),
                  (long)Slot, blockVa);
    return STATUS_SUCCESS;
}

static PVOID
TlsRebaseVa(_In_ UINT64 Va, _In_ UINT64 PreferredBase,
            _In_ UINT64 RemoteBase, _In_ UINT32 ImageSize)
{
    if (Va == 0)
        return NULL;

    if (Va >= RemoteBase && Va < RemoteBase + ImageSize)
        return (PVOID)(ULONG_PTR)Va;

    if (Va >= PreferredBase && Va < PreferredBase + ImageSize)
        return (PVOID)(ULONG_PTR)(RemoteBase + (Va - PreferredBase));

    return NULL;
}

NTSTATUS
AmegerTlsSetup(_In_ PEPROCESS Target, _In_ PVOID RemoteBase,
               _In_ UINT32 PayloadSize, _Out_ LONG *OutSlot,
               _Out_ LONG *OutSeeded)
{
    NTSTATUS status;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_TLS_DIRECTORY64 tlsDir;
    ULONG tlsDirRva;
    ULONG tlsDirSize;
    UINT64 preferred;
    PVOID indexVa;
    PVOID startVa;
    PVOID endVa;
    UINT32 templateSize = 0;
    UINT32 zeroFill = 0;
    PUINT8 template = NULL;
    PAMEGER_TLS_VECTOR vectors = NULL;
    ULONG vectorCount = 0;
    ULONG slot = 0;
    LONG seeded = 0;

    if (OutSlot != NULL) *OutSlot = AMEGER_TLS_SLOT_INVALID;
    if (OutSeeded != NULL) *OutSeeded = 0;
    if (Target == NULL || RemoteBase == NULL || PayloadSize < sizeof(IMAGE_DOS_HEADER))
        return STATUS_INVALID_PARAMETER;

    if (PsGetProcessExitStatus(Target) != STATUS_PENDING)
        return STATUS_PROCESS_IS_TERMINATING;

    status = TlsRead(Target, RemoteBase, &dos, sizeof(dos));
    if (!NT_SUCCESS(status))
        return status;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return STATUS_INVALID_IMAGE_FORMAT;
    if (dos.e_lfanew < 0 ||
        (UINT32)dos.e_lfanew + (UINT32)sizeof(nt) > PayloadSize)
        return STATUS_INVALID_IMAGE_FORMAT;

    status = TlsRead(Target, (PUINT8)RemoteBase + dos.e_lfanew,
                     &nt, sizeof(nt));
    if (!NT_SUCCESS(status))
        return status;
    if (nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return STATUS_INVALID_IMAGE_FORMAT;

    tlsDirRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    tlsDirSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    if (tlsDirRva == 0 || tlsDirSize < sizeof(IMAGE_TLS_DIRECTORY64) ||
        tlsDirRva + (ULONG)sizeof(tlsDir) > PayloadSize)
        return STATUS_NOT_FOUND;

    status = TlsRead(Target, (PUINT8)RemoteBase + tlsDirRva,
                     &tlsDir, sizeof(tlsDir));
    if (!NT_SUCCESS(status))
        return status;

    preferred = nt.OptionalHeader.ImageBase;
    indexVa = TlsRebaseVa(tlsDir.AddressOfIndex, preferred,
                          (UINT64)(ULONG_PTR)RemoteBase, PayloadSize);
    if (indexVa == NULL)
        return STATUS_INVALID_IMAGE_FORMAT;

    startVa = TlsRebaseVa(tlsDir.StartAddressOfRawData, preferred,
                          (UINT64)(ULONG_PTR)RemoteBase, PayloadSize);
    endVa = TlsRebaseVa(tlsDir.EndAddressOfRawData, preferred,
                        (UINT64)(ULONG_PTR)RemoteBase, PayloadSize);

    if (startVa != NULL && endVa != NULL &&
        (UINT_PTR)endVa >= (UINT_PTR)startVa) {
        UINT_PTR size = (UINT_PTR)endVa - (UINT_PTR)startVa;
        if (size > AMEGER_TLS_MAX_TEMPLATE)
            return STATUS_INVALID_IMAGE_FORMAT;
        templateSize = (UINT32)size;
    }
    zeroFill = (UINT32)tlsDir.SizeOfZeroFill;
    if ((SIZE_T)templateSize + zeroFill > AMEGER_TLS_MAX_TEMPLATE)
        return STATUS_INVALID_IMAGE_FORMAT;

    if (templateSize > 0) {
        template = (PUINT8)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                           templateSize, AMEGER_TAG_LOOKUP);
        if (template == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;

        status = TlsRead(Target, startVa, template, templateSize);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(template, AMEGER_TAG_LOOKUP);
            return status;
        }
    }

    status = TlsCollectVectors(Target, &vectors, &vectorCount);
    if (NT_SUCCESS(status)) {
        status = TlsChooseSlot(Target, vectors, vectorCount, &slot);
        if (!NT_SUCCESS(status)) {
            ULONG minLength = AMEGER_TLS_MAX_SLOT;
            ULONG i;

            for (i = 0; i < vectorCount; i++)
                if (vectors[i].Length < minLength)
                    minLength = vectors[i].Length;
            if (minLength >= AMEGER_TLS_MAX_SLOT) {
                ExFreePoolWithTag(vectors, AMEGER_TAG_LOOKUP);
                status = STATUS_NOT_SUPPORTED;
                goto fail_template;
            }
            slot = minLength;
            AmegerDiagLog("[Map] TLS full; vectors=%lu slot=%lu (payload expands)\n",
                          vectorCount, minLength);
            status = STATUS_SUCCESS;
        }
        ExFreePoolWithTag(vectors, AMEGER_TAG_LOOKUP);
        vectors = NULL;
    } else {

        slot = 71;
        AmegerDiagLog("[Map] TLS: no vectors probed; slot=%lu (payload expands)\n", slot);
        status = STATUS_SUCCESS;
    }

    {
        ULONG tlsIndex = slot;

        status = TlsWrite(Target, indexVa, &tlsIndex, sizeof(tlsIndex));
        if (!NT_SUCCESS(status))
            goto fail_template;
    }

    {
        PVOID block = NULL;

        status = TlsAllocateBlock(Target, template, templateSize,
                                  zeroFill, &block);
        if (!NT_SUCCESS(status)) {
            goto fail_template;
        }
        g_TlsBlock = block;
    }
    seeded = 1;

    if (g_TlsTemplate != NULL) {
        ExFreePoolWithTag(g_TlsTemplate, AMEGER_TAG_LOOKUP);
        g_TlsTemplate = NULL;
    }
    g_TlsTemplate = template;
    g_TlsTemplateSize = templateSize;
    g_TlsSizeOfZeroFill = zeroFill;
    g_TlsSlot = (LONG)slot;
    g_TlsProcId = PsGetProcessId(Target);
    InterlockedExchange(&g_TlsInit, 1);

    if (OutSlot != NULL) *OutSlot = (LONG)slot;
    if (OutSeeded != NULL) *OutSeeded = seeded;
    return STATUS_SUCCESS;

fail_template:
    if (template != NULL)
        ExFreePoolWithTag(template, AMEGER_TAG_LOOKUP);
    g_TlsBlock = NULL;
    return status;
}

static VOID
TlsThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    PETHREAD thread = NULL;

    if (!Create)
        return;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return;
    if (InterlockedCompareExchange(&g_TlsInit, 0, 0) == 0)
        return;
    if ((HANDLE)(ULONG_PTR)ProcessId != g_TlsProcId)
        return;
    if (!NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &thread)))
        return;

    (void)AmegerTlsInstallForThread(thread);
    ObDereferenceObject(thread);
}

NTSTATUS
AmegerTlsNotifyArm(VOID)
{
    NTSTATUS status;

    if (!AmegerTlsIsActive())
        return STATUS_NOT_FOUND;

    if (InterlockedCompareExchange(&g_TlsNotifyArmed, 0, 0) != 0) {
        g_TlsNotifyDeadline = KeQueryInterruptTime() + AMEGER_TLS_NOTIFY_100NS;
        return STATUS_SUCCESS;
    }

    status = PsSetCreateThreadNotifyRoutine(TlsThreadNotify);
    if (!NT_SUCCESS(status))
        return status;

    g_TlsNotifyDeadline = KeQueryInterruptTime() + AMEGER_TLS_NOTIFY_100NS;
    InterlockedExchange(&g_TlsNotifyArmed, 1);
    return STATUS_SUCCESS;
}

VOID
AmegerTlsNotifyDisarm(VOID)
{
    if (InterlockedExchange(&g_TlsNotifyArmed, 0) != 0)
        (void)PsRemoveCreateThreadNotifyRoutine(TlsThreadNotify);
    g_TlsNotifyDeadline = 0;
}

VOID
AmegerTlsNotifyTick(VOID)
{
    if (InterlockedCompareExchange(&g_TlsNotifyArmed, 0, 0) == 0)
        return;
    if (KeQueryInterruptTime() >= g_TlsNotifyDeadline)
        AmegerTlsNotifyDisarm();
}

NTSTATUS
AmegerTlsInstallForThread(_In_ PETHREAD Thread)
{
    PEPROCESS proc;

    if (Thread == NULL)
        return STATUS_INVALID_PARAMETER;
    if (!AmegerTlsIsActive())
        return STATUS_NOT_FOUND;

    proc = PsGetThreadProcess(Thread);
    if (proc == NULL)
        return STATUS_NOT_FOUND;
    if ((HANDLE)(ULONG_PTR)PsGetProcessId(proc) != g_TlsProcId)
        return STATUS_NOT_FOUND;

    return TlsBuildTrampoline(proc, Thread, g_TlsSlot,
                              g_TlsTemplate, g_TlsTemplateSize,
                              g_TlsSizeOfZeroFill);
}

NTSTATUS
AmegerTlsGetInstall(_In_ PEPROCESS Target,
                    _Out_ PVOID *OutBlock, _Out_ LONG *OutSlot)
{
    *OutBlock = NULL;
    *OutSlot = -1;

    if (Target == NULL)
        return STATUS_INVALID_PARAMETER;
    if (!AmegerTlsIsActive())
        return STATUS_NOT_FOUND;
    if ((HANDLE)(ULONG_PTR)PsGetProcessId(Target) != g_TlsProcId)
        return STATUS_NOT_FOUND;
    if (g_TlsBlock == NULL)
        return STATUS_NOT_FOUND;

    *OutBlock = g_TlsBlock;
    *OutSlot = g_TlsSlot;
    return STATUS_SUCCESS;
}

VOID
AmegerTlsUnregisterNotify(VOID)
{
    AmegerTlsNotifyDisarm();

    InterlockedExchange(&g_TlsInit, 0);

    if (g_TlsTemplate != NULL) {
        ExFreePoolWithTag(g_TlsTemplate, AMEGER_TAG_LOOKUP);
        g_TlsTemplate = NULL;
    }
    g_TlsTemplateSize = 0;
    g_TlsSizeOfZeroFill = 0;
    g_TlsSlot = AMEGER_TLS_SLOT_INVALID;
    g_TlsProcId = NULL;
    g_TlsBlock = NULL;
}

BOOLEAN
AmegerTlsIsActive(VOID)
{
    return (InterlockedCompareExchange(&g_TlsInit, 0, 0) != 0) &&
           (g_TlsSlot != AMEGER_TLS_SLOT_INVALID);
}

VOID
AmegerTlsPollProcess(_In_ PEPROCESS Target)
{
    LONG slot;
    PUINT8 template;
    UINT32 templateSize;
    UINT32 zeroFill;
    PAMEGER_THREAD_ENTRY entries = NULL;
    ULONG count = 0;
    ULONG i;

    if (Target == NULL || !AmegerTlsIsActive())
        return;
    if ((HANDLE)(ULONG_PTR)PsGetProcessId(Target) != g_TlsProcId)
        return;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return;

    slot = g_TlsSlot;
    template = g_TlsTemplate;
    templateSize = g_TlsTemplateSize;
    zeroFill = g_TlsSizeOfZeroFill;

    if (!NT_SUCCESS(AmegerSnapshotThreads(
            (ULONG)(ULONG_PTR)PsGetProcessId(Target), &entries, &count)))
        return;

    for (i = 0; i < count; i++) {
        PETHREAD thread = NULL;

        if (!NT_SUCCESS(PsLookupThreadByThreadId(
                (HANDLE)(ULONG_PTR)entries[i].ThreadId, &thread)))
            continue;

        (void)TlsInstallOne(Target, thread, slot,
                            template, templateSize, zeroFill);

        ObDereferenceObject(thread);
    }

    AmegerFreeThreads(entries);
}

UINT32
AmegerTlsGetTargetPid(VOID)
{
    if (g_TlsProcId == NULL)
        return 0;
    return (UINT32)(ULONG_PTR)g_TlsProcId;
}
