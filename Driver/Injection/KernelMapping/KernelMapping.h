#pragma once

#include <ntifs.h>
#include <ntimage.h>

#define AMEGER_MAX_IMAGE 0x40000000UL
#define AMEGER_MAX_IMPORT_DLLS 128UL

typedef struct _AMEGER_PE_INFO {

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
} AMEGER_PE_INFO, *PAMEGER_PE_INFO;

NTSTATUS AmegerValidatePe(_In_reads_bytes_(Size) const UINT8 *Buf,
                          _In_ SIZE_T Size,
                          _Out_ PAMEGER_PE_INFO Out);

NTSTATUS AmegerApplyRelocations(_Inout_updates_bytes_(Size) UINT8 *ImageBuf,
                                _In_ SIZE_T Size,
                                _In_ const AMEGER_PE_INFO *Info,
                                _In_ UINT_PTR Delta);

NTSTATUS AmegerWalkImports(_In_ const UINT8 *ImageBuf,
                           _In_ SIZE_T Size,
                           _Inout_ PAMEGER_PE_INFO Info);

PIMAGE_NT_HEADERS64 AmegerGetNtHeaders(_In_reads_bytes_(Size) const UINT8 *Buf,
                                       _In_ SIZE_T Size);
