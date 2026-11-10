#include "DynamicImports.h"
#include "../NT/Definitions.h"

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_      ULONG SystemInformationClass,
    _Inout_   PVOID SystemInformation,
    _In_      ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#ifndef SystemModuleInformation
#define SystemModuleInformation 11
#endif

static BOOLEAN
InjectorAsciiEqI(PCSTR A, PCSTR B)
{
    if (A == NULL || B == NULL)
        return FALSE;
    while (*A && *B) {
        CHAR ca = *A++;
        CHAR cb = *B++;
        if (ca >= 'A' && ca <= 'Z') ca = (CHAR)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = (CHAR)(cb + ('a' - 'A'));
        if (ca != cb)
            return FALSE;
    }
    return (*A == '\0' && *B == '\0');
}

static BOOLEAN
InjectorBoundsOk(PVOID Base, ULONG Size, PVOID Ptr, SIZE_T Need)
{
    UINT_PTR b = (UINT_PTR)Base;
    UINT_PTR p = (UINT_PTR)Ptr;
    UINT_PTR e = b + (UINT_PTR)Size;
    if (p < b)
        return FALSE;
    if (p + (UINT_PTR)Need < p)
        return FALSE;
    if (p + (UINT_PTR)Need > e)
        return FALSE;
    return TRUE;
}

PVOID
InjectorResolveExport(PINJECTOR_EXPORTS Exports,
                    PCSTR ModuleName,
                    PCSTR FunctionName)
{
    PVOID base = Exports->NtoskrnlBase;
    ULONG size = Exports->NtoskrnlSize;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_EXPORT_DIRECTORY exp;
    PULONG names, funcs;
    PUSHORT ords;
    ULONG i, expRva, expSize;

    UNREFERENCED_PARAMETER(ModuleName);

    if (base == NULL || size < sizeof(IMAGE_DOS_HEADER) || FunctionName == NULL)
        return NULL;

    dos = (PIMAGE_DOS_HEADER)base;
    if (!InjectorBoundsOk(base, size, dos, sizeof(IMAGE_DOS_HEADER)))
        return NULL;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    if (dos->e_lfanew <= 0 || (ULONG)dos->e_lfanew > size - sizeof(IMAGE_NT_HEADERS64))
        return NULL;

    nt = (PIMAGE_NT_HEADERS64)((UINT8 *)base + dos->e_lfanew);
    if (!InjectorBoundsOk(base, size, nt, sizeof(IMAGE_NT_HEADERS64)))
        return NULL;
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    expSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (expRva == 0 || expSize == 0 || expRva >= size)
        return NULL;

    exp = (PIMAGE_EXPORT_DIRECTORY)((UINT8 *)base + expRva);
    if (!InjectorBoundsOk(base, size, exp, sizeof(IMAGE_EXPORT_DIRECTORY)))
        return NULL;

    if (exp->AddressOfNames == 0 || exp->AddressOfFunctions == 0 || exp->AddressOfNameOrdinals == 0)
        return NULL;
    if (exp->AddressOfNames >= size || exp->AddressOfFunctions >= size || exp->AddressOfNameOrdinals >= size)
        return NULL;

    names = (PULONG)((UINT8 *)base + exp->AddressOfNames);
    funcs = (PULONG)((UINT8 *)base + exp->AddressOfFunctions);
    ords  = (PUSHORT)((UINT8 *)base + exp->AddressOfNameOrdinals);

    for (i = 0; i < exp->NumberOfNames; i++) {
        ULONG nameRva, funcRva;
        PCSTR name;
        USHORT ord;

        if (!InjectorBoundsOk(base, size, &names[i], sizeof(ULONG)) ||
            !InjectorBoundsOk(base, size, &ords[i], sizeof(USHORT)))
            break;

        nameRva = names[i];
        if (nameRva == 0 || nameRva >= size)
            continue;
        name = (PCSTR)((UINT8 *)base + nameRva);
        if (!InjectorBoundsOk(base, size, (PVOID)name, 1))
            continue;

        if (!InjectorAsciiEqI(name, FunctionName))
            continue;

        ord = ords[i];
        if (ord >= exp->NumberOfFunctions)
            return NULL;
        if (!InjectorBoundsOk(base, size, &funcs[ord], sizeof(ULONG)))
            return NULL;
        funcRva = funcs[ord];
        if (funcRva == 0 || funcRva >= size)
            return NULL;

        if (funcRva >= expRva && funcRva < expRva + expSize)
            return NULL;

        return (PVOID)((UINT8 *)base + funcRva);
    }

    return NULL;
}

NTSTATUS
InjectorExportsInitialize(PINJECTOR_EXPORTS Out)
{
    NTSTATUS status;
    ULONG len = 0;
    PRTL_PROCESS_MODULES mods = NULL;
    ULONG i;
    BOOLEAN found = FALSE;

    if (Out == NULL)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Out, sizeof(*Out));

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
    if (status != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(status) && len == 0)
        return status;
    if (len == 0)
        len = 0x10000;
    len += 0x1000;

    mods = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_PAGED, len, INJECTOR_TAG_LOOKUP);
    if (mods == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemModuleInformation, mods, len, &len);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(mods, INJECTOR_TAG_LOOKUP);
        return status;
    }

    for (i = 0; i < mods->NumberOfModules; i++) {
        PRTL_PROCESS_MODULE_INFORMATION m = &mods->Modules[i];
        PCSTR fn = (PCSTR)m->FullPathName + m->OffsetToFileName;
        if (fn == NULL)
            continue;

        if (!found &&
            (InjectorAsciiEqI(fn, "ntoskrnl.exe") ||
             InjectorAsciiEqI(fn, "ntkrnlmp.exe") ||
             InjectorAsciiEqI(fn, "ntkrnlpa.exe") ||
             InjectorAsciiEqI(fn, "ntkrpamp.exe"))) {
            Out->NtoskrnlBase = m->ImageBase;
            Out->NtoskrnlSize = m->ImageSize;
            found = TRUE;
        }
        if (InjectorAsciiEqI(fn, "storport.sys"))
            Out->StorportBase = m->ImageBase;
        if (InjectorAsciiEqI(fn, "acpi.sys"))
            Out->AcpiBase = m->ImageBase;
        if (InjectorAsciiEqI(fn, "tcpip.sys"))
            Out->TcpipBase = m->ImageBase;
        if (InjectorAsciiEqI(fn, "ndis.sys"))
            Out->NdisBase = m->ImageBase;
    }

    if (!found && mods->NumberOfModules > 0) {
        Out->NtoskrnlBase = mods->Modules[0].ImageBase;
        Out->NtoskrnlSize = mods->Modules[0].ImageSize;
        found = TRUE;
    }

    ExFreePoolWithTag(mods, INJECTOR_TAG_LOOKUP);

    if (!found || Out->NtoskrnlBase == NULL || Out->NtoskrnlSize == 0)
        return STATUS_NOT_FOUND;

    Out->ObRegisterCallbacks   = InjectorResolveExport(Out, "ntoskrnl.exe", "ObRegisterCallbacks");
    Out->ObUnRegisterCallbacks = InjectorResolveExport(Out, "ntoskrnl.exe", "ObUnRegisterCallbacks");
    Out->PsProcessType         = (PVOID *)InjectorResolveExport(Out, "ntoskrnl.exe", "PsProcessType");
    Out->PsThreadType          = (PVOID *)InjectorResolveExport(Out, "ntoskrnl.exe", "PsThreadType");

    if (Out->ObRegisterCallbacks == NULL || Out->ObUnRegisterCallbacks == NULL ||
        Out->PsProcessType == NULL || Out->PsThreadType == NULL) {
        RtlZeroMemory(Out, sizeof(*Out));
        return STATUS_PROCEDURE_NOT_FOUND;
    }

#if DBG
    DbgPrint("[Driver] exports: ntoskrnl=%p size=0x%X\n",
             Out->NtoskrnlBase, Out->NtoskrnlSize);
#endif
    return STATUS_SUCCESS;
}

VOID
InjectorExportsDestroy(PINJECTOR_EXPORTS Exports)
{
    if (Exports != NULL)
        RtlZeroMemory(Exports, sizeof(*Exports));
}
