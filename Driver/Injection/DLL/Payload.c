#include "Payload.h"
#include "../Imports/Imports.h"
#include "../KernelMapping/KernelMapping.h"
#include "../Imports/Imports.h"
#include "../../TLS/TLS.h"
#include "../../Execution/Hijack.h"
#include "../../Core/Communication/Channel/Channel.h"
#include "../../Core/Communication/Mapping/Mapping.h"
#include <ntimage.h>

extern VOID InjectorDiagLog(_In_ PCSTR Format, ...);

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _In_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize);

NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect);

NTKERNELAPI PPEB PsGetProcessPeb(_In_ PEPROCESS Process);

#ifndef STATUS_PROCESS_IS_TERMINATING
#define STATUS_PROCESS_IS_TERMINATING ((NTSTATUS)0xC000010AL)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif

static ULONG
InjectorSectionProtection(_In_ ULONG Characteristics)
{
    if ((Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
        if ((Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
            return PAGE_EXECUTE_READWRITE;
        if ((Characteristics & IMAGE_SCN_MEM_READ) != 0)
            return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if ((Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
        return PAGE_READWRITE;
    if ((Characteristics & IMAGE_SCN_MEM_READ) != 0)
        return PAGE_READONLY;
    return PAGE_NOACCESS;
}

NTSTATUS
DriverKernelValidate(_Inout_ PINJECTOR_CHANNEL Ch,
                     _In_reads_bytes_(Size) const UINT8 *Buf,
                     _In_ UINT32 Size)
{
    INJECTOR_PE_INFO info;
    NTSTATUS status;

    if (Ch == NULL || Buf == NULL || Size == 0)
        return STATUS_INVALID_PARAMETER;

    status = InjectorValidatePe(Buf, Size, &info);
    if (!NT_SUCCESS(status))
        return status;

    status = InjectorWalkImports(Buf, Size, &info);
    if (!NT_SUCCESS(status))
        return status;

    InterlockedExchange64((volatile LONG64 *)&Ch->RelocCount, (LONG64)info.RelocCount);
    InterlockedExchange64((volatile LONG64 *)&Ch->ImportDllCount, (LONG64)info.ImportDllCount);
    InterlockedExchange64((volatile LONG64 *)&Ch->RemoteBase, 0);

#if DBG
    DbgPrint("[Driver] validate ok: image=0x%X reloc=%u imports=%u\n",
             info.SizeOfImage, info.RelocCount, info.ImportDllCount);
#endif

    return STATUS_SUCCESS;
}

/*
 * Map an image into the target: create a section, publish it in the system
 * address space, copy the headers and sections, map it into the target,
 * apply the relocations and resolve the imports.
 *
 * Shared by the payload itself and by the dependency loader, which uses it
 * to bring a module the target has not loaded into the target's address
 * space.
 */
NTSTATUS
InjectorMapImageIntoTarget(_In_ PEPROCESS Target,
                           _In_reads_bytes_(Size) const UINT8 *Buf,
                           _In_ SIZE_T Size,
                           _Out_ PVOID *OutBase,
                           _Out_ PVOID *OutSysView,
                           _Out_ PHANDLE OutProcess,
                           _Out_ PINJECTOR_PE_INFO OutInfo,
                           _In_ BOOLEAN AllowDependencyLoad)
{
    INJECTOR_PE_INFO info;
    PIMAGE_NT_HEADERS64 nt = NULL;
    HANDLE hSection = NULL;
    HANDLE hProcess = NULL;
    PVOID sysView = NULL;
    PVOID remoteBase = NULL;
    SIZE_T sysViewSize = 0;
    SIZE_T remoteSize = 0;
    LARGE_INTEGER maxSize;
    OBJECT_ATTRIBUTES sectionOa;
    NTSTATUS status;
    ULONG i;
    const IMAGE_SECTION_HEADER *sec = NULL;

    *OutBase = NULL;
    *OutSysView = NULL;
    if (OutProcess != NULL)
        *OutProcess = NULL;

    if (Target == NULL || Buf == NULL || Size == 0 ||
        OutBase == NULL || OutSysView == NULL)
        return STATUS_INVALID_PARAMETER;

    status = InjectorValidatePe(Buf, Size, &info);
    if (!NT_SUCCESS(status))
        return status;

    status = InjectorWalkImports(Buf, Size, &info);
    if (!NT_SUCCESS(status))
        return status;

    nt = InjectorGetNtHeaders(Buf, Size);
    if (nt == NULL)
        return STATUS_INVALID_IMAGE_FORMAT;

    InitializeObjectAttributes(&sectionOa, NULL,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);
    maxSize.QuadPart = (LONGLONG)info.SizeOfImage;
    status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &sectionOa,
                             &maxSize, PAGE_EXECUTE_READWRITE,
                             SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) {
        InjectorDiagLog("[Map] ZwCreateSection failed: 0x%08X\n", status);
        goto fail;
    }

    sysViewSize = (SIZE_T)info.SizeOfImage;
    status = InjectorMapSectionInSystemSpace(hSection, &sysView, &sysViewSize);
    if (!NT_SUCCESS(status)) {
        InjectorDiagLog("[Map] system view failed: 0x%08X\n", status);
        goto fail;
    }
    if (sysView == NULL) {
        InjectorDiagLog("[Map] system view mapped to NULL\n");
        status = STATUS_UNSUCCESSFUL;
        goto fail;
    }

    {
        SIZE_T hdrSize = info.SizeOfHeaders;
        if (hdrSize > (SIZE_T)Size)
            hdrSize = (SIZE_T)Size;
        if (hdrSize > (SIZE_T)info.SizeOfImage)
            hdrSize = (SIZE_T)info.SizeOfImage;
        if (hdrSize > 0)
            RtlCopyMemory(sysView, Buf, hdrSize);
    }

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        SIZE_T va = (SIZE_T)sec[i].VirtualAddress;
        SIZE_T raw = (SIZE_T)sec[i].SizeOfRawData;
        SIZE_T src = (SIZE_T)sec[i].PointerToRawData;

        if (raw == 0)
            continue;
        if (va + raw <= (SIZE_T)info.SizeOfImage &&
            src + raw <= (SIZE_T)Size) {
            RtlCopyMemory((PUINT8)sysView + va, Buf + src, raw);
        }
    }

    status = ObOpenObjectByPointer(Target, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_VM_OPERATION,
                                   *PsProcessType, KernelMode, &hProcess);
    if (!NT_SUCCESS(status)) {
        InjectorDiagLog("[Map] ObOpenObjectByPointer failed: 0x%08X\n", status);
        goto fail;
    }

    remoteBase = NULL;
    remoteSize = (SIZE_T)info.SizeOfImage;
    status = ZwMapViewOfSection(hSection, hProcess, &remoteBase, 0, 0,
                                NULL, &remoteSize, ViewUnmap, 0,
                                PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        InjectorDiagLog("[Map] ZwMapViewOfSection failed: 0x%08X\n", status);
        goto fail;
    }

    InjectorDiagLog("[Map] pid=%lu base=%p size=0x%X preferred=0x%llX\n",
                  (unsigned long)(ULONG_PTR)PsGetProcessId(Target),
                  remoteBase, info.SizeOfImage,
                  (unsigned long long)info.PreferredBase);

    if (info.PreferredBase != 0) {
        UINT_PTR delta = (UINT_PTR)remoteBase - (UINT_PTR)info.PreferredBase;
        if (delta != 0) {
            if (!info.HasRelocations) {
                /*
                 * The image was not mapped at its preferred base and cannot
                 * be fixed up.  Mapping it anyway would leave absolute
                 * addresses pointing at the wrong place.
                 */
                InjectorDiagLog("[Map] no relocations but base moved by 0x%llX\n",
                                (unsigned long long)delta);
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto fail;
            }
            status = InjectorApplyRelocations((UINT8 *)sysView,
                                            (SIZE_T)info.SizeOfImage,
                                            &info, delta);
            if (!NT_SUCCESS(status)) {
                InjectorDiagLog("[Map] relocations failed: 0x%08X\n", status);
                goto fail;
            }
        }
    }

    status = InjectorResolveImports(Target, (UINT8 *)sysView,
                                    info.SizeOfImage, AllowDependencyLoad);
    if (!NT_SUCCESS(status)) {
        InjectorDiagLog("[Map] import resolution failed: 0x%08X\n", status);
        goto fail;
    }

    *OutBase = remoteBase;
    *OutSysView = sysView;
    if (OutProcess != NULL)
        *OutProcess = hProcess;
    else
        ZwClose(hProcess);
    if (OutInfo != NULL)
        *OutInfo = info;

    ZwClose(hSection);
    return STATUS_SUCCESS;

fail:
    if (remoteBase != NULL && hProcess != NULL)
        (void)ZwUnmapViewOfSection(hProcess, remoteBase);
    if (sysView != NULL)
        InjectorUnmapSectionInSystemSpace(sysView);
    if (hProcess != NULL)
        ZwClose(hProcess);
    if (hSection != NULL)
        ZwClose(hSection);
    return status;
}

NTSTATUS
DriverKernelMap(_Inout_ PINJECTOR_CHANNEL Ch,
                _In_reads_bytes_(Size) const UINT8 *Buf,
                _In_ UINT32 Size)
{
    INJECTOR_PE_INFO info;
    PIMAGE_NT_HEADERS64 nt = NULL;
    PEPROCESS proc = NULL;
    HANDLE hSection = NULL;
    HANDLE hProcess = NULL;
    PVOID sysView = NULL;
    PVOID remoteBase = NULL;
    BOOLEAN remoteMapped = FALSE;
    NTSTATUS status;
    NTSTATUS tlsStatus;
    ULONG i;
    const IMAGE_SECTION_HEADER *sec = NULL;
    LONG tlsSlot = INJECTOR_TLS_SLOT_INVALID;
    LONG tlsSeeded = 0;

    if (Ch == NULL || Buf == NULL || Size == 0)
        return STATUS_INVALID_PARAMETER;

    status = InjectorValidatePe(Buf, Size, &info);
    if (!NT_SUCCESS(status))
        return status;

    status = InjectorWalkImports(Buf, Size, &info);
    if (!NT_SUCCESS(status))
        return status;

    if (Ch->Pid == 0)
        return STATUS_INVALID_PARAMETER;

    nt = InjectorGetNtHeaders(Buf, Size);
    if (nt == NULL)
        return STATUS_INVALID_IMAGE_FORMAT;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Ch->Pid, &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        if (NT_SUCCESS(status))
            status = STATUS_INVALID_PARAMETER;
        return status;
    }

    if (PsGetProcessExitStatus(proc) != STATUS_PENDING) {
        ObDereferenceObject(proc);
        return STATUS_PROCESS_IS_TERMINATING;
    }
    if (PsGetProcessPeb(proc) == NULL) {
        ObDereferenceObject(proc);
        return STATUS_NOT_FOUND;
    }

    InjectorResetDependencyCount();
    status = InjectorMapImageIntoTarget(proc, Buf, (SIZE_T)Size,
                                        &remoteBase, &sysView,
                                        &hProcess, &info, TRUE);
    if (!NT_SUCCESS(status))
        goto fail;

    /*
     * A dependency the target was missing: it has been mapped, so register
     * it under its own name and stop - the client maps the real payload
     * next and the import resolver finds this one through the registry.
     */
    if ((Ch->Flags & INJECTOR_FLAG_DEPENDENCY) != 0) {
        CHAR depName[256];

        InjectorGetImageExportName((UINT8 *)sysView, (SIZE_T)info.SizeOfImage,
                                   depName);
        if (depName[0] != '\0') {
            InjectorRegisterInjectedModule(depName, remoteBase);
            InjectorDiagLog("[Deps] %s mapped into the target base=%p\n",
                          depName, remoteBase);
        }
        Ch->RemoteBase = (volatile unsigned long long)(ULONG_PTR)remoteBase;
        Ch->CmdStatus = (LONG)STATUS_SUCCESS;
        if (hProcess != NULL)
            ZwClose(hProcess);
        if (sysView != NULL)
            InjectorUnmapSectionInSystemSpace(sysView);
        ObDereferenceObject(proc);
        return STATUS_SUCCESS;
    }

    Ch->DependencyCount = InjectorGetDependencyCount();
    if (Ch->DependencyCount != 0)
        InjectorDiagLog("[Map] %u dependency module(s) loaded into the target\n",
                      (unsigned)Ch->DependencyCount);

    tlsStatus = InjectorTlsSetup(proc, remoteBase, info.SizeOfImage,
                               &tlsSlot, &tlsSeeded);
    if (tlsStatus == STATUS_NOT_FOUND) {
        InjectorDiagLog("[Map] TLS: none\n");
        InterlockedExchange(&Ch->TlsSlot, INJECTOR_TLS_SLOT_INVALID);
        InterlockedExchange(&Ch->TlsStatus, (LONG)STATUS_SUCCESS);
        InterlockedExchange(&Ch->TlsThreadsSeeded, 0);
    } else if (NT_SUCCESS(tlsStatus)) {
        InjectorDiagLog("[Map] TLS: slot=%ld seeded=%ld\n",
                      (long)tlsSlot, (long)tlsSeeded);
        InterlockedExchange(&Ch->TlsSlot, tlsSlot);
        InterlockedExchange(&Ch->TlsStatus, (LONG)STATUS_SUCCESS);
        InterlockedExchange(&Ch->TlsThreadsSeeded, tlsSeeded);
    } else {
        InjectorDiagLog("[Map] TLS failed: status=0x%08X\n", tlsStatus);
        InterlockedExchange(&Ch->TlsSlot, INJECTOR_TLS_SLOT_INVALID);
        InterlockedExchange(&Ch->TlsStatus, (LONG)tlsStatus);
        InterlockedExchange(&Ch->TlsThreadsSeeded, 0);
        status = tlsStatus;
        goto fail;
    }

    {
        PVOID addr = remoteBase;
        SIZE_T sz = (SIZE_T)info.SizeOfHeaders;
        ULONG oldProt = 0;

        if (sz > (SIZE_T)info.SizeOfImage)
            sz = (SIZE_T)info.SizeOfImage;
        if (sz > 0) {
            status = ZwProtectVirtualMemory(hProcess, &addr, &sz,
                                            PAGE_READONLY, &oldProt);
            if (!NT_SUCCESS(status)) {
                InjectorDiagLog("[Map] protect headers failed: 0x%08X\n", status);
                goto fail;
            }
        }
    }

    /*
     * The section table pointer is derived from the image's own NT headers.
     * It must be re-derived here: the mapping itself works on a copy in the
     * system view, and a stale or null section table would fault the kernel
     * when the sections are protected.
     */
    nt = InjectorGetNtHeaders(Buf, (SIZE_T)Size);
    if (nt == NULL) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto fail;
    }
    sec = IMAGE_FIRST_SECTION(nt);
    if (sec == NULL) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto fail;
    }

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        ULONG prot = InjectorSectionProtection(sec[i].Characteristics);
        PVOID addr;
        SIZE_T sz;
        ULONG oldProt = 0;

        sz = (SIZE_T)sec[i].Misc.VirtualSize;
        if (sz == 0)
            sz = (SIZE_T)sec[i].SizeOfRawData;
        if (sz == 0)
            continue;

        if (prot == PAGE_EXECUTE_READWRITE) {
            InjectorDiagLog("[Map] refusing RWX section %u\n", i);
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto fail;
        }

        addr = (PUINT8)remoteBase + sec[i].VirtualAddress;
        status = ZwProtectVirtualMemory(hProcess, &addr, &sz, prot, &oldProt);
        if (!NT_SUCCESS(status)) {
            InjectorDiagLog("[Map] protect section %u (0x%X) failed: 0x%08X\n",
                          i, prot, status);
            goto fail;
        }
    }

    {
        ULONGLONG inst[2] = { 0, 0xFFFFFFFFFFFFFFFFULL };
        ULONG gRva = 0;
        NTSTATUS instStatus;

        instStatus = InjectorFindImageExport((UINT8 *)sysView,
                                           info.SizeOfImage,
                                           "g_InjectorTlsInstall", &gRva);
        if (NT_SUCCESS(instStatus) &&
            (UINT64)gRva + sizeof(inst) <= (UINT64)info.SizeOfImage) {
            PVOID tlsBlock = NULL;
            LONG instSlot = -1;
            ULONGLONG check[2] = { 0, 0 };

            if (tlsStatus == STATUS_SUCCESS &&
                NT_SUCCESS(InjectorTlsGetInstall(proc, &tlsBlock, &instSlot))) {
                inst[0] = (ULONGLONG)(ULONG_PTR)tlsBlock;
                inst[1] = (ULONGLONG)(ULONG)instSlot;
            }
            RtlCopyMemory((PUINT8)sysView + gRva, inst, sizeof(inst));
            RtlCopyMemory(check, (PUINT8)sysView + gRva, sizeof(check));
            if (check[0] != inst[0] || check[1] != inst[1]) {
                InjectorDiagLog("[Map] g_InjectorTlsInstall write verification FAILED "
                              "(expected {%llx,%llx}, got {%llx,%llx})\n",
                              inst[0], inst[1], check[0], check[1]);
                status = STATUS_UNSUCCESSFUL;
                goto fail;
            }
            InjectorDiagLog("[Map] g_InjectorTlsInstall <- block=0x%p slot=%ld (tlsStatus=0x%08X) verified\n",
                          (PVOID)(ULONG_PTR)inst[0],
                          inst[1] == 0xFFFFFFFFFFFFFFFFULL ? -1 : (LONG)inst[1],
                          tlsStatus);
        } else {
            InjectorDiagLog("[Map] g_InjectorTlsInstall export not found (0x%08X)\n",
                          instStatus);
        }
    }

    {
        ULONGLONG baseVal = (ULONGLONG)(ULONG_PTR)remoteBase;
        ULONGLONG probe = 0;
        ULONG imgRva = 0;
        NTSTATUS imgStatus;

        imgStatus = InjectorFindImageExport((UINT8 *)sysView,
                                          info.SizeOfImage,
                                          "g_InjectorImageBase", &imgRva);
        if (NT_SUCCESS(imgStatus) &&
            (UINT64)imgRva + sizeof(baseVal) <= (UINT64)info.SizeOfImage) {
            RtlCopyMemory((PUINT8)sysView + imgRva, &baseVal, sizeof(baseVal));
            RtlCopyMemory(&probe, (PUINT8)sysView + imgRva, sizeof(probe));
            if (probe != baseVal) {
                InjectorDiagLog("[Map] g_InjectorImageBase write verification FAILED "
                              "(expected 0x%llx, got 0x%llx)\n",
                              baseVal, probe);
                status = STATUS_UNSUCCESSFUL;
                goto fail;
            } else {
                InjectorDiagLog("[Map] g_InjectorImageBase <- base=0x%llx verified\n",
                              baseVal);
            }
        } else {
            InjectorDiagLog("[Map] g_InjectorImageBase export not found (0x%08X)\n",
                          imgStatus);
        }
    }

    {
        const UINT64 chVa  = (UINT64)INJECTOR_CHANNEL_USER_VA;
        const UINT64 chEnd = chVa + (UINT64)INJECTOR_CHANNEL_TOTAL_SIZE;
        const UINT64 pBase = (UINT64)(ULONG_PTR)remoteBase;
        const UINT64 pEnd  = pBase + (UINT64)info.SizeOfImage;

        if (pBase < chEnd && pEnd > chVa) {
            InjectorDiagLog("[Map] channel map skipped: payload [0x%llX,0x%llX) "
                          "covers channel VA 0x%llX; SelfTestAck will not work\n",
                          pBase, pEnd, chVa);
        } else {
            NTSTATUS chMapStatus = InjectorChannelMapIntoProcess(proc);
            InjectorDiagLog("[Map] channel map into target: 0x%08X\n", chMapStatus);
        }
    }

    InterlockedExchange64((volatile LONG64 *)&Ch->RemoteBase,
                          (LONG64)(ULONG_PTR)remoteBase);
    InterlockedExchange64((volatile LONG64 *)&Ch->RelocCount,
                          (LONG64)info.RelocCount);
    InterlockedExchange64((volatile LONG64 *)&Ch->ImportDllCount,
                          (LONG64)info.ImportDllCount);

    InjectorDiagLog("[Map] success: base=%p\n", remoteBase);

    InjectorUnmapSectionInSystemSpace(sysView);
    ZwClose(hSection);
    ZwClose(hProcess);
    ObDereferenceObject(proc);
    return STATUS_SUCCESS;

fail:
    if (remoteMapped && hProcess != NULL)
        (void)ZwUnmapViewOfSection(hProcess, remoteBase);
    if (sysView != NULL)
        InjectorUnmapSectionInSystemSpace(sysView);
    if (hSection != NULL)
        ZwClose(hSection);
    if (hProcess != NULL)
        ZwClose(hProcess);
    ObDereferenceObject(proc);
    return status;
}

NTSTATUS
DriverKernelExec(_Inout_ PINJECTOR_CHANNEL Ch)
{
    PEPROCESS proc = NULL;
    UINT32 pid;
    UINT64 remoteBase;
    NTSTATUS status;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    SIZE_T done = 0;
    UINT32 imageSize;

    if (Ch == NULL)
        return STATUS_INVALID_PARAMETER;

    pid = Ch->Pid;
    remoteBase = Ch->RemoteBase;
    if (pid == 0 || remoteBase == 0)
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(status) || proc == NULL)
        return status;

    if (PsGetProcessExitStatus(proc) != STATUS_PENDING) {
        ObDereferenceObject(proc);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    RtlZeroMemory(&dos, sizeof(dos));
    status = MmCopyVirtualMemory(proc, (PVOID)(ULONG_PTR)remoteBase,
                                 PsGetCurrentProcess(), &dos,
                                 sizeof(dos), KernelMode, &done);
    if (!NT_SUCCESS(status) || done != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) {
        ObDereferenceObject(proc);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    RtlZeroMemory(&nt, sizeof(nt));
    status = MmCopyVirtualMemory(proc,
                                 (PUINT8)(ULONG_PTR)remoteBase + dos.e_lfanew,
                                 PsGetCurrentProcess(), &nt,
                                 sizeof(nt), KernelMode, &done);
    if (!NT_SUCCESS(status) || done != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        ObDereferenceObject(proc);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    imageSize = nt.OptionalHeader.SizeOfImage;

    status = DriverKernelExecute(Ch, proc, Ch->ExecutionVa,
                                 remoteBase, imageSize);

    ObDereferenceObject(proc);
    return status;
}
