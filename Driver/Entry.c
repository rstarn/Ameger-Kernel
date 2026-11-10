#include "Core/Communication/Channel/Channel.h"
#include "Core/Communication/Mapping/Mapping.h"
#include "Core/Dispatch/Dispatcher.h"
#include "Core/Dispatch/Polling/Poll.h"
#include "Native/DynamicImports.h"
#include "TLS/TLS.h"
#include "Stealth/ObCallback.h"

static INJECTOR_EXPORTS g_Exports;

static VOID
InjectorDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    InjectorCommandShutdown();
    InjectorPollShutdown();

    InjectorTlsUnregisterNotify();
    InjectorObCallbackShutdown();
    InjectorChannelDestroy();
    InjectorExportsDestroy(&g_Exports);
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
            _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    if (DriverObject == NULL) return STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(RegistryPath);

    {
        UNICODE_STRING logPath;
        OBJECT_ATTRIBUTES oa;
        RtlInitUnicodeString(&logPath,
                             L"\\SystemRoot\\Temp\\injector_diag.log");
        InitializeObjectAttributes(&oa, &logPath,
                                   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                   NULL, NULL);
        (void)ZwDeleteFile(&oa);
    }

    DriverObject->DriverUnload = InjectorDriverUnload;

    status = InjectorExportsInitialize(&g_Exports);
    if (!NT_SUCCESS(status)) {
#if DBG
        DbgPrint("[Driver] exports init failed: 0x%08X\n", status);
#endif
        return status;
    }

    status = InjectorChannelInitialize();
    if (!NT_SUCCESS(status)) {
#if DBG
        DbgPrint("[Driver] channel init failed: 0x%08X\n", status);
#endif
        InjectorExportsDestroy(&g_Exports);
        return status;
    }

    (void)InjectorChannelMapExisting();

    status = InjectorCommandInitialize();
    if (!NT_SUCCESS(status)) {
#if DBG
        DbgPrint("[Driver] command init failed: 0x%08X\n", status);
#endif
        InjectorChannelDestroy();
        InjectorExportsDestroy(&g_Exports);
        return status;
    }

    status = InjectorPollInitialize();
    if (!NT_SUCCESS(status)) {
#if DBG
        DbgPrint("[Driver] poll init failed: 0x%08X\n", status);
#endif

    }

    status = InjectorObCallbackInitialize(&g_Exports);
    if (!NT_SUCCESS(status)) {
#if DBG
        DbgPrint("[Driver] ob callback init failed: 0x%08X (non-fatal)\n", status);
#endif

    }

#if DBG
    DbgPrint("[Driver] loaded. ntoskrnl=0x%p size=0x%X\n",
             g_Exports.NtoskrnlBase, g_Exports.NtoskrnlSize);
#endif

    return STATUS_SUCCESS;
}
