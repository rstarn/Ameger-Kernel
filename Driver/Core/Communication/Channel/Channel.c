#include "Channel.h"
#include "../../../NT/Definitions.h"

#ifndef STATUS_INVALID_DEVICE_STATE
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184L)
#endif
#ifndef STATUS_PROCEDURE_NOT_FOUND
#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS)0xC000007AL)
#endif

typedef NTSTATUS (NTAPI *PFN_MmMapViewInSystemSpace)(
    _In_ PVOID Section,
    _Out_ PVOID *MappedBase,
    _Inout_ PSIZE_T ViewSize);
typedef NTSTATUS (NTAPI *PFN_MmUnmapViewInSystemSpace)(
    _In_ PVOID MappedBase);

static PFN_MmMapViewInSystemSpace   g_pMmMapViewInSystemSpace   = NULL;
static PFN_MmUnmapViewInSystemSpace g_pMmUnmapViewInSystemSpace = NULL;

static PAMEGER_CHANNEL g_Channel = NULL;
static HANDLE          g_SectionHandle = NULL;
static PVOID           g_KernelView = NULL;
static PUINT8          g_PayloadBuffer = NULL;

static NTSTATUS
AmegerResolveSystemViewApis(VOID)
{
    UNICODE_STRING us;

    if (g_pMmMapViewInSystemSpace == NULL) {
        RtlInitUnicodeString(&us, L"MmMapViewInSystemSpace");
        g_pMmMapViewInSystemSpace =
            (PFN_MmMapViewInSystemSpace)MmGetSystemRoutineAddress(&us);
    }
    if (g_pMmUnmapViewInSystemSpace == NULL) {
        RtlInitUnicodeString(&us, L"MmUnmapViewInSystemSpace");
        g_pMmUnmapViewInSystemSpace =
            (PFN_MmUnmapViewInSystemSpace)MmGetSystemRoutineAddress(&us);
    }

    if (g_pMmMapViewInSystemSpace == NULL ||
        g_pMmUnmapViewInSystemSpace == NULL) {
#if DBG
        DbgPrint("[Driver] FATAL: MmMapViewInSystemSpace not resolved\n");
#endif
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
AmegerMapSectionInSystemSpace(_In_ HANDLE SectionHandle,
                              _Out_ PVOID *MappedBase,
                              _Inout_ PSIZE_T ViewSize)
{
    NTSTATUS status;
    PVOID sectionObject = NULL;
    PVOID base = NULL;
    SIZE_T size;

    if (SectionHandle == NULL ||
        MappedBase == NULL || ViewSize == NULL || *ViewSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    status = AmegerResolveSystemViewApis();
    if (!NT_SUCCESS(status))
        return status;

    status = ObReferenceObjectByHandle(SectionHandle,
                                       SECTION_MAP_READ | SECTION_MAP_WRITE,
                                       NULL,
                                       KernelMode,
                                       &sectionObject,
                                       NULL);
    if (!NT_SUCCESS(status))
        return status;

    size = *ViewSize;
    status = g_pMmMapViewInSystemSpace(sectionObject, &base, &size);
    ObDereferenceObject(sectionObject);
    if (!NT_SUCCESS(status))
        return status;

    *MappedBase = base;
    *ViewSize = size;
    return STATUS_SUCCESS;
}

VOID
AmegerUnmapSectionInSystemSpace(_In_ PVOID MappedBase)
{
    if (MappedBase != NULL && g_pMmUnmapViewInSystemSpace != NULL)
        (void)g_pMmUnmapViewInSystemSpace(MappedBase);
}

NTSTATUS
AmegerChannelInitialize(VOID)
{
    NTSTATUS status;
    LARGE_INTEGER maxSize;
    SIZE_T viewSize = AMEGER_CHANNEL_TOTAL_SIZE;
    PAMEGER_CHANNEL ch;
    OBJECT_ATTRIBUTES sectionOa;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    if (g_SectionHandle != NULL)
        return STATUS_ALREADY_REGISTERED;

    status = AmegerResolveSystemViewApis();
    if (!NT_SUCCESS(status))
        return status;

    InitializeObjectAttributes(&sectionOa, NULL,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    maxSize.QuadPart = AMEGER_CHANNEL_TOTAL_SIZE;
    status = ZwCreateSection(&g_SectionHandle,
                             SECTION_MAP_READ | SECTION_MAP_WRITE,
                             &sectionOa, &maxSize, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status))
        return status;

    status = AmegerMapSectionInSystemSpace(g_SectionHandle,
                                           &g_KernelView, &viewSize);
    if (!NT_SUCCESS(status)) {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        return status;
    }

    ch = (PAMEGER_CHANNEL)g_KernelView;
    RtlZeroMemory(ch, AMEGER_CHANNEL_TOTAL_SIZE);
    ch->Magic      = AMEGER_CHANNEL_MAGIC;
    ch->AbiVersion = AMEGER_CHANNEL_ABI_VERSION;
    g_Channel = ch;

    g_PayloadBuffer = (PUINT8)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        AMEGER_PAYLOAD_BUF_SIZE,
        AMEGER_TAG_LOOKUP);
    if (g_PayloadBuffer == NULL) {
        AmegerUnmapSectionInSystemSpace(g_KernelView);
        g_KernelView = NULL;
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        g_Channel = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

#if DBG
    DbgPrint("[Driver] channel kernel VA=%p (user VA=0x%llX) payload=%p magic=%016llX abi=%u\n",
             g_KernelView, (unsigned long long)AMEGER_CHANNEL_USER_VA,
             g_PayloadBuffer,
             (unsigned long long)AMEGER_CHANNEL_MAGIC,
             AMEGER_CHANNEL_ABI_VERSION);
#endif
    return STATUS_SUCCESS;
}

VOID
AmegerChannelDestroy(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;

    if (g_PayloadBuffer != NULL) {
        ExFreePoolWithTag(g_PayloadBuffer, AMEGER_TAG_LOOKUP);
        g_PayloadBuffer = NULL;
    }
    if (g_KernelView != NULL) {
        AmegerUnmapSectionInSystemSpace(g_KernelView);
        g_KernelView = NULL;
    }
    if (g_SectionHandle != NULL) {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
    }
    g_Channel = NULL;
}

PAMEGER_CHANNEL AmegerChannelGet(VOID)             { return g_Channel; }
HANDLE          AmegerChannelGetSectionHandle(VOID){ return g_SectionHandle; }
PUINT8          AmegerChannelGetPayloadBuffer(VOID){ return g_PayloadBuffer; }
UINT32          AmegerChannelGetPayloadBufferSize(VOID){ return AMEGER_PAYLOAD_BUF_SIZE; }
