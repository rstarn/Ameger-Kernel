#include "KernelMapping.h"

static NTSTATUS
AmegerRvaToFileRange(_In_ const IMAGE_NT_HEADERS64 *Nt,
                     _In_ ULONG Rva,
                     _In_ ULONG Length,
                     _In_ SIZE_T FileSize,
                     _Out_ SIZE_T *FileOffset)
{
    const IMAGE_SECTION_HEADER *sec;
    ULONG i;

    if (Nt == NULL || FileOffset == NULL || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Rva < Nt->OptionalHeader.SizeOfHeaders) {
        if ((SIZE_T)Rva + Length > Nt->OptionalHeader.SizeOfHeaders ||
            (SIZE_T)Rva + Length > FileSize) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        *FileOffset = (SIZE_T)Rva;
        return STATUS_SUCCESS;
    }

    sec = IMAGE_FIRST_SECTION(Nt);
    for (i = 0; i < Nt->FileHeader.NumberOfSections; i++) {
        ULONG va = sec[i].VirtualAddress;
        ULONG rawSize = sec[i].SizeOfRawData;
        ULONG virtSize = sec[i].Misc.VirtualSize;
        ULONG span = (virtSize > rawSize) ? virtSize : rawSize;
        ULONG delta;

        if (rawSize == 0 || Rva < va) {
            continue;
        }
        delta = Rva - va;
        if (delta >= span) {
            continue;
        }
        if (delta >= rawSize) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        if ((SIZE_T)delta + Length > rawSize ||
            (SIZE_T)sec[i].PointerToRawData + delta + Length > FileSize) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        *FileOffset = (SIZE_T)sec[i].PointerToRawData + delta;
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_IMAGE_FORMAT;
}

NTSTATUS AmegerValidatePe(_In_reads_bytes_(Size) const UINT8 *Buf,
                          _In_ SIZE_T Size,
                          _Out_ PAMEGER_PE_INFO Out)
{
    const IMAGE_DOS_HEADER *dos = NULL;
    const IMAGE_NT_HEADERS64 *nt = NULL;
    const IMAGE_SECTION_HEADER *sec = NULL;
    ULONG i = 0;
    ULONG relocRva = 0;
    ULONG relocSize = 0;
    ULONG importRva = 0;
    ULONG importSize = 0;
    ULONG dirCount = 0;

    if (Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Out, sizeof(AMEGER_PE_INFO));

    if (Buf == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Size < sizeof(IMAGE_DOS_HEADER)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    dos = (const IMAGE_DOS_HEADER *)Buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (dos->e_lfanew < 0) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if ((SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > Size) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    nt = (const IMAGE_NT_HEADERS64 *)(Buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (nt->FileHeader.NumberOfSections == 0 || nt->FileHeader.NumberOfSections > 96) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (nt->OptionalHeader.SizeOfImage == 0 || nt->OptionalHeader.SizeOfImage > AMEGER_MAX_IMAGE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if ((SIZE_T)nt->OptionalHeader.SizeOfHeaders > Size) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData != 0) {
            if ((SIZE_T)sec[i].PointerToRawData + (SIZE_T)sec[i].SizeOfRawData > Size) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }
    }

    Out->SizeOfImage = nt->OptionalHeader.SizeOfImage;
    Out->SizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    Out->PreferredBase = nt->OptionalHeader.ImageBase;

    dirCount = nt->OptionalHeader.NumberOfRvaAndSizes;
    if (dirCount > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        relocRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        relocSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }
    if (dirCount > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        importRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    Out->BaseRelocRva = relocRva;
    Out->BaseRelocSize = relocSize;
    Out->ImportRva = importRva;
    Out->ImportSize = importSize;

    Out->HasRelocations = FALSE;
    Out->RelocCount = 0;
    if (relocRva != 0 && relocSize != 0) {
        SIZE_T relocOff = 0;

        if (!NT_SUCCESS(AmegerRvaToFileRange(nt, relocRva, relocSize,
                                             Size, &relocOff))) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        Out->HasRelocations = TRUE;

        {
            const UINT8 *p = Buf + relocOff;
            const UINT8 *end = Buf + relocOff + relocSize;
            while (p < end) {
                const IMAGE_BASE_RELOCATION *block = (const IMAGE_BASE_RELOCATION *)p;
                if ((const UINT8 *)block + sizeof(IMAGE_BASE_RELOCATION) > end) {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }
                if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }
                if ((const UINT8 *)block + block->SizeOfBlock > end) {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }
                {
                    ULONG count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
                    const USHORT *entries = (const USHORT *)(block + 1);
                    ULONG e = 0;
                    for (e = 0; e < count; e++) {
                        USHORT type = (USHORT)(entries[e] >> 12);
                        if (type == IMAGE_REL_BASED_ABSOLUTE) {
                            continue;
                        }
                        if (type == IMAGE_REL_BASED_DIR64) {
                            Out->RelocCount++;
                            continue;
                        }
                        return STATUS_INVALID_IMAGE_FORMAT;
                    }
                }
                p += block->SizeOfBlock;
            }
        }
    }

    Out->HasImports = FALSE;
    Out->ImportDllCount = 0;
    if (importRva != 0 && importSize != 0) {
        SIZE_T importOff = 0;

        if (!NT_SUCCESS(AmegerRvaToFileRange(nt, importRva, importSize,
                                             Size, &importOff))) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        Out->HasImports = TRUE;

        {
            const IMAGE_IMPORT_DESCRIPTOR *desc =
                (const IMAGE_IMPORT_DESCRIPTOR *)(Buf + importOff);
            const UINT8 *impEnd = Buf + importOff + importSize;
            while (TRUE) {
                SIZE_T nameOff = 0;

                if ((const UINT8 *)desc + sizeof(IMAGE_IMPORT_DESCRIPTOR) > impEnd) {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }
                if (desc->Name == 0) {
                    break;
                }
                if (!NT_SUCCESS(AmegerRvaToFileRange(nt, desc->Name, 1,
                                                     Size, &nameOff)) ||
                    Buf[nameOff] == '\0') {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }
                Out->ImportDllCount++;
                if (Out->ImportDllCount > AMEGER_MAX_IMPORT_DLLS) {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }
                desc++;
            }
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS AmegerApplyRelocations(_Inout_updates_bytes_(Size) UINT8 *ImageBuf,
                                _In_ SIZE_T Size,
                                _In_ const AMEGER_PE_INFO *Info,
                                _In_ UINT_PTR Delta)
{
    if (ImageBuf == NULL || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Delta == 0) {
        return STATUS_SUCCESS;
    }

    if (!Info->HasRelocations) {
        return STATUS_SUCCESS;
    }

    if (Info->BaseRelocRva == 0 || Info->BaseRelocSize == 0) {
        return STATUS_SUCCESS;
    }

    {
        PIMAGE_NT_HEADERS64 nt = AmegerGetNtHeaders(ImageBuf, Size);
        BOOLEAN imageLayout = (Info->SizeOfImage != 0 &&
                               (SIZE_T)Info->SizeOfImage <= Size);
        SIZE_T relocOff = 0;

        if (imageLayout) {
            if ((SIZE_T)Info->BaseRelocRva + (SIZE_T)Info->BaseRelocSize > Size) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            relocOff = (SIZE_T)Info->BaseRelocRva;
        } else {
            if (nt == NULL) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            if (!NT_SUCCESS(AmegerRvaToFileRange(nt, Info->BaseRelocRva,
                                                 Info->BaseRelocSize,
                                                 Size, &relocOff))) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }

        {
            UINT8 *p = ImageBuf + relocOff;
            UINT8 *end = ImageBuf + relocOff + Info->BaseRelocSize;
        while (p < end) {
            IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)p;
            if ((UINT8 *)block + sizeof(IMAGE_BASE_RELOCATION) > end) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            if ((UINT8 *)block + block->SizeOfBlock > end) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            {
                ULONG count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
                USHORT *entries = (USHORT *)(block + 1);
                ULONG e = 0;
                for (e = 0; e < count; e++) {
                    USHORT type = (USHORT)(entries[e] >> 12);
                    USHORT off = (USHORT)(entries[e] & 0x0FFF);
                    if (type == IMAGE_REL_BASED_ABSOLUTE) {
                        continue;
                    }
                    if (type != IMAGE_REL_BASED_DIR64) {
                        return STATUS_INVALID_IMAGE_FORMAT;
                    }
                    {
                        UINT_PTR patchOff = (UINT_PTR)block->VirtualAddress + (UINT_PTR)off;
                        UINT_PTR patchTarget = 0;

                        if (imageLayout) {
                            if (patchOff + sizeof(UINT_PTR) > Size) {
                                return STATUS_INVALID_IMAGE_FORMAT;
                            }
                            patchTarget = patchOff;
                        } else {
                            SIZE_T patchFile = 0;
                            if (!NT_SUCCESS(AmegerRvaToFileRange(nt, (ULONG)patchOff,
                                                                 sizeof(UINT_PTR),
                                                                 Size, &patchFile))) {
                                return STATUS_INVALID_IMAGE_FORMAT;
                            }
                            patchTarget = (UINT_PTR)patchFile;
                        }
                        *(UINT_PTR *)(ImageBuf + patchTarget) += (UINT_PTR)Delta;
                    }
                }
            }
            p += block->SizeOfBlock;
        }
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS AmegerWalkImports(_In_ const UINT8 *ImageBuf,
                           _In_ SIZE_T Size,
                           _Inout_ PAMEGER_PE_INFO Info)
{
    PIMAGE_NT_HEADERS64 nt;
    SIZE_T importOff = 0;

    if (ImageBuf == NULL || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Info->HasImports) {
        Info->ImportDllCount = 0;
        return STATUS_SUCCESS;
    }

    if (Info->ImportRva == 0 || Info->ImportSize == 0) {
        Info->HasImports = FALSE;
        Info->ImportDllCount = 0;
        return STATUS_SUCCESS;
    }

    nt = AmegerGetNtHeaders(ImageBuf, Size);
    if (nt == NULL) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (!NT_SUCCESS(AmegerRvaToFileRange(nt, Info->ImportRva, Info->ImportSize,
                                         Size, &importOff))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    Info->ImportDllCount = 0;
    {
        const IMAGE_IMPORT_DESCRIPTOR *desc =
            (const IMAGE_IMPORT_DESCRIPTOR *)(ImageBuf + importOff);
        const UINT8 *impEnd = ImageBuf + importOff + Info->ImportSize;
        while (TRUE) {
            SIZE_T nameOff = 0;

            if ((const UINT8 *)desc + sizeof(IMAGE_IMPORT_DESCRIPTOR) > impEnd) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            if (desc->Name == 0) {
                break;
            }
            if (!NT_SUCCESS(AmegerRvaToFileRange(nt, desc->Name, 1,
                                                 Size, &nameOff)) ||
                ImageBuf[nameOff] == '\0') {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            Info->ImportDllCount++;
            if (Info->ImportDllCount > AMEGER_MAX_IMPORT_DLLS) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            desc++;
        }
    }

    return STATUS_SUCCESS;
}

PIMAGE_NT_HEADERS64 AmegerGetNtHeaders(_In_reads_bytes_(Size) const UINT8 *Buf,
                                       _In_ SIZE_T Size)
{
    const IMAGE_DOS_HEADER *dos = NULL;
    const IMAGE_NT_HEADERS64 *nt = NULL;

    if (Buf == NULL || Size < sizeof(IMAGE_DOS_HEADER)) {
        return NULL;
    }

    dos = (const IMAGE_DOS_HEADER *)Buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    if (dos->e_lfanew < 0) {
        return NULL;
    }
    if ((SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > Size) {
        return NULL;
    }

    nt = (const IMAGE_NT_HEADERS64 *)(Buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        return NULL;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return NULL;
    }

    return (PIMAGE_NT_HEADERS64)((ULONG_PTR)nt);
}
