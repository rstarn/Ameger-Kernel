#include "Imports.h"
#include "../../NT/Definitions.h"
#include <ntimage.h>
#include <ntdef.h>

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _In_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize);

NTKERNELAPI PPEB PsGetProcessPeb(_In_ PEPROCESS Process);

extern VOID AmegerDiagLog(_In_ PCSTR Format, ...);

#define AMEGER_IMPORT_MAX_DLLS        64
#define AMEGER_IMPORT_MAX_FUNCS       8192
#define AMEGER_IMPORT_MAX_NAMES       8192
#define AMEGER_IMPORT_MAX_THUNKS      4096
#define AMEGER_IMPORT_MAX_FORWARD     2
#define AMEGER_USER_MIN               0x10000ULL
#define AMEGER_USER_MAX               0x00007FFFFFFF0000ULL
#define AMEGER_MODULE_NAME_MAX        256
#define AMEGER_RESOLVE_NAME_MAX       256

static NTSTATUS
ImportRead(_In_ PEPROCESS Target, _In_ PVOID Remote,
           _Out_writes_bytes_(Size) PVOID Local, _In_ SIZE_T Size)
{
    NTSTATUS status;
    SIZE_T done = 0;

    if ((ULONG_PTR)Remote < AMEGER_USER_MIN ||
        (ULONG_PTR)Remote >= AMEGER_USER_MAX)
        return STATUS_INVALID_ADDRESS;

    status = MmCopyVirtualMemory(Target, Remote,
                                 PsGetCurrentProcess(), Local,
                                 Size, KernelMode, &done);
    if (NT_SUCCESS(status) && done != Size)
        return STATUS_PARTIAL_COPY;
    return status;
}

static BOOLEAN
WideStrICmp(_In_ const USHORT *Wide, _In_ SIZE_T WideChars,
            _In_ const char *Ascii)
{
    SIZE_T i;

    for (i = 0; i < WideChars && Ascii[i] != '\0'; i++) {
        UCHAR wc = (UCHAR)(Wide[i] & 0xFF);
        UCHAR ac = (UCHAR)Ascii[i];

        if (Wide[i] > 0x7F)
            return FALSE;
        if (wc >= 'A' && wc <= 'Z') wc = (UCHAR)(wc + 32);
        if (ac >= 'A' && ac <= 'Z') ac = (UCHAR)(ac + 32);
        if (wc != ac)
            return FALSE;
    }
    return Ascii[i] == '\0' && i == WideChars;
}

static BOOLEAN
AsciiICmp(_In_ const char *A, _In_ const char *B)
{
    SIZE_T i = 0;

    for (;;) {
        UCHAR a = (UCHAR)A[i], b = (UCHAR)B[i];

        if (a >= 'A' && a <= 'Z') a = (UCHAR)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (UCHAR)(b + 32);
        if (a != b)
            return FALSE;
        if (a == '\0')
            return TRUE;
        i++;
        if (i > AMEGER_MODULE_NAME_MAX)
            return FALSE;
    }
}

static BOOLEAN
AsciiNICmp(_In_ const char *A, _In_ const char *B, _In_ SIZE_T N)
{
    SIZE_T i;

    for (i = 0; i < N && A[i] != '\0' && B[i] != '\0'; i++) {
        UCHAR a = (UCHAR)A[i], b = (UCHAR)B[i];

        if (a >= 'A' && a <= 'Z') a = (UCHAR)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (UCHAR)(b + 32);
        if (a != b)
            return FALSE;
    }
    return i == N || A[i] == '\0' || B[i] == '\0';
}

static NTSTATUS
ImportFindModule(_In_ PEPROCESS Target, _In_ const char *DllName,
                 _Out_ PVOID *OutBase)
{
    PPEB peb;
    PVOID ldr = NULL;
    UCHAR headBytes[sizeof(LIST_ENTRY)];
    ULONG_PTR headVA;
    ULONG_PTR cur;
    ULONG i;

    *OutBase = NULL;

    peb = PsGetProcessPeb(Target);
    if (peb == NULL)
        return STATUS_NOT_FOUND;

    if (!NT_SUCCESS(ImportRead(Target,
                               (PUINT8)peb + 0x18,
                               &ldr, sizeof(ldr))) || ldr == NULL)
        return STATUS_NOT_FOUND;

    if (!NT_SUCCESS(ImportRead(Target,
                               (PUINT8)ldr + 0x20,
                               headBytes, sizeof(headBytes))))
        return STATUS_NOT_FOUND;

    headVA = (ULONG_PTR)ldr + 0x20;
    cur = *(ULONG_PTR *)headBytes;

    for (i = 0; i < 512; i++) {
        UCHAR entry[0x70];
        PVOID dllBase;
        USHORT nameLen;
        PVOID nameBuf;
        SIZE_T nameChars;

        if (cur == headVA)
            break;
        if (cur < AMEGER_USER_MIN || cur >= AMEGER_USER_MAX)
            return STATUS_INVALID_ADDRESS;

        if (!NT_SUCCESS(ImportRead(Target, (PVOID)(cur - 0x10),
                                   entry, sizeof(entry))))
            return STATUS_PARTIAL_COPY;

        dllBase = *(PVOID *)(entry + 0x30);
        nameLen = *(USHORT *)(entry + 0x58);
        nameBuf = *(PVOID *)(entry + 0x60);

        if (dllBase != NULL && nameBuf != NULL &&
            nameLen > 0 && nameLen <= AMEGER_MODULE_NAME_MAX * 2) {
            USHORT wide[AMEGER_MODULE_NAME_MAX];

            if (NT_SUCCESS(ImportRead(Target, nameBuf, wide, nameLen))) {
                nameChars = nameLen / 2;
                if (WideStrICmp(wide, nameChars, DllName)) {
                    *OutBase = dllBase;
                    return STATUS_SUCCESS;
                }
            }
        }

        cur = *(ULONG_PTR *)(entry + 0x10);
    }

    return STATUS_NOT_FOUND;
}

typedef struct _AMEGER_EXPORT_VIEW {
    PVOID     ModuleBase;
    ULONG     NumberOfFunctions;
    ULONG     NumberOfNames;
    ULONG     Base;
    PULONG    Functions;
    PULONG    Names;
    PUSHORT   Ordinals;
    ULONG     ExportRva;
    ULONG     ExportSize;
} AMEGER_EXPORT_VIEW, *PAMEGER_EXPORT_VIEW;

static VOID
ImportFreeExportView(_In_ PAMEGER_EXPORT_VIEW V)
{
    if (V->Functions != NULL) ExFreePoolWithTag(V->Functions, AMEGER_TAG_IMPORTS);
    if (V->Names != NULL)     ExFreePoolWithTag(V->Names, AMEGER_TAG_IMPORTS);
    if (V->Ordinals != NULL)  ExFreePoolWithTag(V->Ordinals, AMEGER_TAG_IMPORTS);
    RtlZeroMemory(V, sizeof(*V));
}

static NTSTATUS
ImportOpenExportView(_In_ PEPROCESS Target, _In_ PVOID ModuleBase,
                     _Out_ PAMEGER_EXPORT_VIEW V)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY expDir;
    IMAGE_EXPORT_DIRECTORY edf;
    SIZE_T nFunc, nNames;
    NTSTATUS status;

    RtlZeroMemory(V, sizeof(*V));
    V->ModuleBase = ModuleBase;

    status = ImportRead(Target, ModuleBase, &dos, sizeof(dos));
    if (!NT_SUCCESS(status))
        return status;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
        return STATUS_INVALID_IMAGE_FORMAT;

    status = ImportRead(Target, (PUINT8)ModuleBase + dos.e_lfanew,
                        &nt, sizeof(nt));
    if (!NT_SUCCESS(status))
        return status;
    if (nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return STATUS_INVALID_IMAGE_FORMAT;

    expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0 || expDir.Size == 0)
        return STATUS_NOT_FOUND;

    status = ImportRead(Target,
                        (PUINT8)ModuleBase + expDir.VirtualAddress,
                        &edf, sizeof(edf));
    if (!NT_SUCCESS(status))
        return status;
    if (edf.NumberOfFunctions > AMEGER_IMPORT_MAX_FUNCS ||
        edf.NumberOfNames > AMEGER_IMPORT_MAX_NAMES)
        return STATUS_INVALID_IMAGE_FORMAT;

    nFunc = edf.NumberOfFunctions;
    nNames = edf.NumberOfNames;

    V->NumberOfFunctions = edf.NumberOfFunctions;
    V->NumberOfNames = edf.NumberOfNames;
    V->Base = edf.Base;
    V->ExportRva = expDir.VirtualAddress;
    V->ExportSize = expDir.Size;

    V->Functions = (PULONG)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                           nFunc * sizeof(ULONG),
                                           AMEGER_TAG_IMPORTS);
    V->Names = (PULONG)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                       nNames * sizeof(ULONG),
                                       AMEGER_TAG_IMPORTS);
    V->Ordinals = (PUSHORT)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                           nNames * sizeof(USHORT),
                                           AMEGER_TAG_IMPORTS);
    if (V->Functions == NULL || V->Names == NULL || V->Ordinals == NULL) {
        ImportFreeExportView(V);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ImportRead(Target, (PUINT8)ModuleBase + edf.AddressOfFunctions,
                        V->Functions, nFunc * sizeof(ULONG));
    if (!NT_SUCCESS(status)) goto fail;
    status = ImportRead(Target, (PUINT8)ModuleBase + edf.AddressOfNames,
                        V->Names, nNames * sizeof(ULONG));
    if (!NT_SUCCESS(status)) goto fail;
    status = ImportRead(Target, (PUINT8)ModuleBase + edf.AddressOfNameOrdinals,
                        V->Ordinals, nNames * sizeof(USHORT));
    if (!NT_SUCCESS(status)) goto fail;
    return STATUS_SUCCESS;

fail:
    ImportFreeExportView(V);
    return status;
}

static NTSTATUS
ImportResolveOne(_In_ PEPROCESS Target, _In_ PVOID ModuleBase,
                 _In_ const char *Symbol, _In_ ULONG Depth,
                 _Out_ PVOID *OutVa)
{
    AMEGER_EXPORT_VIEW view;
    NTSTATUS status;
    ULONG i;

    *OutVa = NULL;

    status = ImportOpenExportView(Target, ModuleBase, &view);
    if (!NT_SUCCESS(status))
        return status;

    status = STATUS_NOT_FOUND;

    for (i = 0; i < view.NumberOfNames; i++) {
        char name[AMEGER_RESOLVE_NAME_MAX];
        USHORT ord;
        ULONG funcRva;
        PVOID va;

        RtlZeroMemory(name, sizeof(name));
        if (!NT_SUCCESS(ImportRead(Target,
                                   (PUINT8)ModuleBase + view.Names[i],
                                   name, sizeof(name) - 1)))
            continue;
        name[sizeof(name) - 1] = '\0';
        if (!AsciiICmp(name, Symbol))
            continue;

        ord = view.Ordinals[i];
        if (ord >= view.NumberOfFunctions)
            continue;
        funcRva = view.Functions[ord];
        if (funcRva == 0)
            continue;

        if (funcRva >= view.ExportRva &&
            funcRva < view.ExportRva + view.ExportSize) {
            char fwd[AMEGER_MODULE_NAME_MAX];
            char fwdModule[AMEGER_MODULE_NAME_MAX];
            char fwdSymbol[AMEGER_MODULE_NAME_MAX];
            char *dot;
            PVOID fwdBase = NULL;
            SIZE_T mi, si;
            NTSTATUS fwdStatus;

            if (Depth + 1 >= AMEGER_IMPORT_MAX_FORWARD)
                break;

            RtlZeroMemory(fwd, sizeof(fwd));
            if (!NT_SUCCESS(ImportRead(Target,
                                       (PUINT8)ModuleBase + funcRva,
                                       fwd, sizeof(fwd) - 1)))
                break;
            fwd[sizeof(fwd) - 1] = '\0';

            dot = NULL;
            for (mi = 0; fwd[mi] != '\0' && mi < sizeof(fwd) - 1; mi++)
                if (fwd[mi] == '.') { dot = &fwd[mi]; break; }
            if (dot == NULL || dot == fwd)
                break;

            for (mi = 0; &fwd[mi] < dot; mi++)
                fwdModule[mi] = fwd[mi];
            fwdModule[mi] = '\0';
            si = 0;
            for (mi = (dot - fwd) + 1; fwd[mi] != '\0' && si < sizeof(fwdSymbol) - 1; mi++, si++)
                fwdSymbol[si] = fwd[mi];
            fwdSymbol[si] = '\0';

            {
                SIZE_T ml = 0;

                while (fwdModule[ml] != '\0') ml++;
                if (ml >= 4 && AsciiNICmp(&fwdModule[ml - 4], ".dll", 4)) {

                } else {
                    if (ml + 4 < sizeof(fwdModule)) {
                        fwdModule[ml + 0] = '.';
                        fwdModule[ml + 1] = 'd';
                        fwdModule[ml + 2] = 'l';
                        fwdModule[ml + 3] = 'l';
                        fwdModule[ml + 4] = '\0';
                    }
                }
            }

            fwdStatus = ImportFindModule(Target, fwdModule, &fwdBase);
            if (!NT_SUCCESS(fwdStatus)) {
                AmegerDiagLog("[Imports] forwarder module %s not loaded (from %s!%s)\n",
                              fwdModule, (const char *)Symbol, fwdModule);
                break;
            }
            fwdStatus = ImportResolveOne(Target, fwdBase, fwdSymbol,
                                         Depth + 1, OutVa);
            status = fwdStatus;
            goto out;
        }

        va = (PUINT8)ModuleBase + funcRva;
        *OutVa = va;
        status = STATUS_SUCCESS;
        goto out;
    }

out:
    ImportFreeExportView(&view);
    return status;
}

NTSTATUS
AmegerFindImageExport(_In_ UINT8 *Image,
                      _In_ UINT32 ImageSize,
                      _In_ const char *Symbol,
                      _Out_ ULONG *OutRva)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY expDir;
    IMAGE_EXPORT_DIRECTORY edf;
    UINT32 i;
    UINT32 NumberOfFunctions;
    UINT32 NumberOfNames;
    UINT64 funcsOff;
    UINT64 namesOff;
    UINT64 ordsOff;

    *OutRva = 0;

    if (Image == NULL || Symbol == NULL)
        return STATUS_INVALID_PARAMETER;

    if (ImageSize < sizeof(IMAGE_DOS_HEADER))
        return STATUS_INVALID_IMAGE_FORMAT;

    RtlCopyMemory(&dos, Image, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 ||
        (UINT32)dos.e_lfanew + (UINT32)sizeof(nt) > ImageSize)
        return STATUS_INVALID_IMAGE_FORMAT;

    RtlCopyMemory(&nt, Image + dos.e_lfanew, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return STATUS_INVALID_IMAGE_FORMAT;

    expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0 ||
        (UINT64)expDir.VirtualAddress + sizeof(edf) > ImageSize)
        return STATUS_NOT_FOUND;

    RtlCopyMemory(&edf, Image + expDir.VirtualAddress, sizeof(edf));
    if (edf.NumberOfNames > AMEGER_IMPORT_MAX_NAMES ||
        edf.NumberOfFunctions > AMEGER_IMPORT_MAX_FUNCS)
        return STATUS_INVALID_IMAGE_FORMAT;

    NumberOfNames = edf.NumberOfNames;
    NumberOfFunctions = edf.NumberOfFunctions;

    funcsOff = (UINT64)edf.AddressOfFunctions;
    namesOff = (UINT64)edf.AddressOfNames;
    ordsOff = (UINT64)edf.AddressOfNameOrdinals;

    if (namesOff + (UINT64)NumberOfNames * sizeof(ULONG) > ImageSize)
        return STATUS_INVALID_IMAGE_FORMAT;
    if (ordsOff + (UINT64)NumberOfNames * sizeof(USHORT) > ImageSize)
        return STATUS_INVALID_IMAGE_FORMAT;
    if (funcsOff + (UINT64)NumberOfFunctions * sizeof(ULONG) > ImageSize)
        return STATUS_INVALID_IMAGE_FORMAT;

    for (i = 0; i < NumberOfNames; i++) {
        ULONG nameRva;
        const char *name;
        ULONG ord;
        ULONG funcRva;
        SIZE_T j;

        RtlCopyMemory(&nameRva, Image + namesOff + (UINT64)i * sizeof(ULONG),
                      sizeof(nameRva));
        if (nameRva >= ImageSize)
            continue;

        name = (const char *)(Image + nameRva);
        for (j = 0; j <= AMEGER_MODULE_NAME_MAX; j++) {
            UCHAR a;
            UCHAR b;

            if (j >= ImageSize - nameRva)
                goto next;
            a = (UCHAR)name[j];
            b = (UCHAR)Symbol[j];

            if (a >= 'A' && a <= 'Z') a = (UCHAR)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (UCHAR)(b + 32);
            if (a != b)
                goto next;
            if (a == '\0')
                break;
        }

        USHORT ord16 = 0;
        RtlCopyMemory(&ord16, Image + ordsOff + (UINT64)i * sizeof(USHORT),
                      sizeof(USHORT));
        ord = (ULONG)ord16;
        if (ord >= NumberOfFunctions)
            continue;

        RtlCopyMemory(&funcRva, Image + funcsOff + (UINT64)ord * sizeof(ULONG),
                      sizeof(ULONG));
        if (funcRva == 0 || funcRva >= ImageSize)
            continue;

        *OutRva = funcRva;
        return STATUS_SUCCESS;

next:
        continue;
    }

    return STATUS_NOT_FOUND;
}

static const char *
ImportRealModuleName(_In_ const char *Name)
{
    if (AsciiNICmp(Name, "api-ms-win-crt-", 15))
        return "ucrtbase.dll";
    if (AsciiICmp(Name, "vcruntime140.dll") ||
        AsciiICmp(Name, "vcruntime140"))
        return "ucrtbase.dll";
    return Name;
}

NTSTATUS
AmegerResolveImports(_In_ PEPROCESS Target,
                     _In_ UINT8 *Image,
                     _In_ UINT32 ImageSize)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY impDir;
    UINT32 i;
    UINT32 failCount = 0;
    UINT32 descCount = 0;

    if (Target == NULL || Image == NULL)
        return STATUS_INVALID_PARAMETER;

    RtlCopyMemory(&dos, Image, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 ||
        (UINT32)dos.e_lfanew + (UINT32)sizeof(nt) > ImageSize)
        return STATUS_INVALID_IMAGE_FORMAT;

    RtlCopyMemory(&nt, Image + dos.e_lfanew, sizeof(nt));
    if (nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return STATUS_INVALID_IMAGE_FORMAT;

    impDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0 || impDir.Size == 0) {
        AmegerDiagLog("[Imports] payload has no imports\n");
        return STATUS_SUCCESS;
    }
    if (impDir.VirtualAddress + impDir.Size > ImageSize)
        return STATUS_INVALID_IMAGE_FORMAT;

    AmegerDiagLog("[Imports] resolving %u bytes of descriptors\n", impDir.Size);

    for (i = 0; ; i++) {
        IMAGE_IMPORT_DESCRIPTOR desc;
        UINT64 descOffset = (UINT64)impDir.VirtualAddress +
                            (UINT64)i * sizeof(desc);
        const char *realName;
        char dllName[AMEGER_MODULE_NAME_MAX];
        PVOID modBase = NULL;
        ULONGLONG va = 0;
        ULONG thunk;
        NTSTATUS st;
        UINT64 iatBase;
        UINT64 oft;

        if (i >= AMEGER_IMPORT_MAX_DLLS)
            return STATUS_INVALID_IMAGE_FORMAT;
        if (descOffset + sizeof(desc) >
            (UINT64)impDir.VirtualAddress + impDir.Size)
            return STATUS_INVALID_IMAGE_FORMAT;

        RtlCopyMemory(&desc, Image + descOffset, sizeof(desc));
        if (desc.Name == 0 && desc.OriginalFirstThunk == 0 &&
            desc.FirstThunk == 0)
            break;

        if (desc.Name >= ImageSize)
            return STATUS_INVALID_IMAGE_FORMAT;

        RtlZeroMemory(dllName, sizeof(dllName));
        {
            SIZE_T j;

            for (j = 0; j < sizeof(dllName) - 1 &&
                        desc.Name + j < ImageSize; j++) {
                dllName[j] = (char)Image[desc.Name + j];
                if (dllName[j] == '\0')
                    break;
            }
            dllName[sizeof(dllName) - 1] = '\0';
        }

        realName = ImportRealModuleName(dllName);

        st = ImportFindModule(Target, realName, &modBase);
        if (!NT_SUCCESS(st)) {
            AmegerDiagLog("[Imports] FAIL: module %s (as %s) not loaded in target\n",
                          dllName, realName);
            failCount++;
            continue;
        }

        oft = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk
                                           : desc.FirstThunk;
        if (oft >= ImageSize || desc.FirstThunk >= ImageSize)
            return STATUS_INVALID_IMAGE_FORMAT;

        iatBase = desc.FirstThunk;
        AmegerDiagLog("[Imports] %s -> base=%p\n", realName, modBase);

        for (thunk = 0; ; thunk++) {
            UINT64 thunkValue;
            ULONGLONG rva;

            if (thunk >= AMEGER_IMPORT_MAX_THUNKS)
                return STATUS_INVALID_IMAGE_FORMAT;
            if (oft + (UINT64)thunk * 8 + 8 > ImageSize)
                return STATUS_INVALID_IMAGE_FORMAT;
            if (iatBase + (UINT64)thunk * 8 + 8 > ImageSize)
                return STATUS_INVALID_IMAGE_FORMAT;

            RtlCopyMemory(&thunkValue, Image + oft + thunk * 8,
                          sizeof(thunkValue));
            if (thunkValue == 0)
                break;

            if ((thunkValue & 0x8000000000000000ULL) != 0) {
                ULONG ord = (ULONG)(thunkValue & 0xFFFF);
                AMEGER_EXPORT_VIEW view;
                NTSTATUS ost;

                ost = ImportOpenExportView(Target, modBase, &view);
                if (NT_SUCCESS(ost)) {
                    if (ord >= view.Base &&
                        (ord - view.Base) < view.NumberOfFunctions &&
                        view.Functions[ord - view.Base] != 0)
                        va = (ULONGLONG)((PUINT8)modBase +
                                         view.Functions[ord - view.Base]);
                    else
                        ost = STATUS_NOT_FOUND;
                    ImportFreeExportView(&view);
                }
                if (!NT_SUCCESS(ost)) {
                    AmegerDiagLog("[Imports] FAIL: %s!ordinal:%lu\n",
                                  realName, ord);
                    failCount++;
                    continue;
                }
            } else {
                char symName[AMEGER_RESOLVE_NAME_MAX];

                rva = thunkValue & 0xFFFFFFFFULL;
                if (rva + 2 >= ImageSize)
                    return STATUS_INVALID_IMAGE_FORMAT;
                RtlZeroMemory(symName, sizeof(symName));
                if (rva + 2 + sizeof(symName) - 1 > ImageSize)
                    return STATUS_INVALID_IMAGE_FORMAT;
                RtlCopyMemory(symName, Image + rva + 2,
                              sizeof(symName) - 1);
                symName[sizeof(symName) - 1] = '\0';

                {
                    PVOID resolvedVa = NULL;

                    st = ImportResolveOne(Target, modBase, symName,
                                          0, &resolvedVa);
                    va = (ULONGLONG)(ULONG_PTR)resolvedVa;
                }
                if (!NT_SUCCESS(st)) {
                    AmegerDiagLog("[Imports] FAIL: %s!%s (0x%08llX)\n",
                                  realName, symName, thunkValue);
                    failCount++;
                    continue;
                }
            }

            RtlCopyMemory(Image + iatBase + (UINT64)thunk * 8,
                          &va, sizeof(va));
        }

        descCount++;
    }

    AmegerDiagLog("[Imports] done: %u descriptors, %u unresolved\n",
                  descCount, failCount);

    if (failCount != 0)
        return STATUS_NOT_FOUND;
    return STATUS_SUCCESS;
}
