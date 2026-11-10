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

static PINJECTOR_CHANNEL g_Channel = NULL;
static HANDLE          g_SectionHandle = NULL;
static PVOID           g_KernelView = NULL;
static PUINT8          g_PayloadBuffer = NULL;

static NTSTATUS
InjectorResolveSystemViewApis(VOID)
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
InjectorMapSectionInSystemSpace(_In_ HANDLE SectionHandle,
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

    status = InjectorResolveSystemViewApis();
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
InjectorUnmapSectionInSystemSpace(_In_ PVOID MappedBase)
{
    if (MappedBase != NULL && g_pMmUnmapViewInSystemSpace != NULL)
        (void)g_pMmUnmapViewInSystemSpace(MappedBase);
}

NTSTATUS
InjectorChannelInitialize(VOID)
{
    NTSTATUS status;
    LARGE_INTEGER maxSize;
    SIZE_T viewSize = INJECTOR_CHANNEL_TOTAL_SIZE;
    PINJECTOR_CHANNEL ch;
    OBJECT_ATTRIBUTES sectionOa;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    if (g_SectionHandle != NULL)
        return STATUS_ALREADY_REGISTERED;

    status = InjectorResolveSystemViewApis();
    if (!NT_SUCCESS(status))
        return status;

    InitializeObjectAttributes(&sectionOa, NULL,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    maxSize.QuadPart = INJECTOR_CHANNEL_TOTAL_SIZE;
    status = ZwCreateSection(&g_SectionHandle,
                             SECTION_MAP_READ | SECTION_MAP_WRITE,
                             &sectionOa, &maxSize, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status))
        return status;

    status = InjectorMapSectionInSystemSpace(g_SectionHandle,
                                           &g_KernelView, &viewSize);
    if (!NT_SUCCESS(status)) {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        return status;
    }

    ch = (PINJECTOR_CHANNEL)g_KernelView;
    RtlZeroMemory(ch, INJECTOR_CHANNEL_TOTAL_SIZE);
    ch->Magic      = INJECTOR_CHANNEL_MAGIC;
    ch->AbiVersion = INJECTOR_CHANNEL_ABI_VERSION;
    g_Channel = ch;

    g_PayloadBuffer = (PUINT8)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        INJECTOR_PAYLOAD_BUF_SIZE,
        INJECTOR_TAG_LOOKUP);
    if (g_PayloadBuffer == NULL) {
        InjectorUnmapSectionInSystemSpace(g_KernelView);
        g_KernelView = NULL;
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        g_Channel = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

#if DBG
    DbgPrint("[Driver] channel kernel VA=%p (user VA=0x%llX) payload=%p magic=%016llX abi=%u\n",
             g_KernelView, (unsigned long long)INJECTOR_CHANNEL_USER_VA,
             g_PayloadBuffer,
             (unsigned long long)INJECTOR_CHANNEL_MAGIC,
             INJECTOR_CHANNEL_ABI_VERSION);
#endif
    return STATUS_SUCCESS;
}

VOID
InjectorChannelDestroy(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;

    if (g_PayloadBuffer != NULL) {
        ExFreePoolWithTag(g_PayloadBuffer, INJECTOR_TAG_LOOKUP);
        g_PayloadBuffer = NULL;
    }
    if (g_KernelView != NULL) {
        InjectorUnmapSectionInSystemSpace(g_KernelView);
        g_KernelView = NULL;
    }
    if (g_SectionHandle != NULL) {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
    }
    g_Channel = NULL;
}

PINJECTOR_CHANNEL InjectorChannelGet(VOID)             { return g_Channel; }
HANDLE          InjectorChannelGetSectionHandle(VOID){ return g_SectionHandle; }
PUINT8          InjectorChannelGetPayloadBuffer(VOID){ return g_PayloadBuffer; }
UINT32          InjectorChannelGetPayloadBufferSize(VOID){ return INJECTOR_PAYLOAD_BUF_SIZE; }
