#pragma once

#include <ntifs.h>
#include <ntimage.h>

#define INJECTOR_MAX_IMAGE 0x40000000UL
#define INJECTOR_MAX_IMPORT_DLLS 128UL

typedef struct _INJECTOR_PE_INFO {

    ULONG  SizeOfHeaders;
    ULONG  BaseRelocRva;
    ULONG  BaseRelocSize;
    ULONG  ImportRva;
    ULONG  ImportSize;
    ULONG  RelocCount;
    ULONG  ImportDllCount;
    BOOLEAN HasRelocations;
    BOOLEAN HasImports;
    UINT64 PreferredBase;
    UINT32 SizeOfImage;
} INJECTOR_PE_INFO, *PINJECTOR_PE_INFO;

NTSTATUS InjectorValidatePe(_In_reads_bytes_(Size) const UINT8 *Buf,
                          _In_ SIZE_T Size,
                          _Out_ PINJECTOR_PE_INFO Out);

NTSTATUS InjectorApplyRelocations(_Inout_updates_bytes_(Size) UINT8 *ImageBuf,
                                _In_ SIZE_T Size,
                                _In_ const INJECTOR_PE_INFO *Info,
                                _In_ UINT_PTR Delta);

NTSTATUS InjectorWalkImports(_In_ const UINT8 *ImageBuf,
                           _In_ SIZE_T Size,
                           _Inout_ PINJECTOR_PE_INFO Info);

PIMAGE_NT_HEADERS64 InjectorGetNtHeaders(_In_reads_bytes_(Size) const UINT8 *Buf,
                                       _In_ SIZE_T Size);

/* Read the image's own module name out of its export directory.  Works on a
   mapped image, where the RVA is the offset. */
VOID InjectorGetImageExportName(_In_reads_bytes_(Size) const UINT8 *Image,
                                _In_ SIZE_T Size,
                                _Out_ CHAR OutName[256]);
