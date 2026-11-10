
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <winnt.h>
#include <stdarg.h>
#include <tlhelp32.h>

#ifndef INJECTOR_CHANNEL_MAGIC
#define INJECTOR_CHANNEL_MAGIC 0x1122334455667788ULL
#endif
#include "../../Driver/Core/Communication/Offsets.h"

#define INJECTOR_CHANNEL_RING_SIZE  0x4000
#define INJECTOR_CHANNEL_HEADER_SIZE 0x1000
#define INJECTOR_CHANNEL_TOTAL_SIZE (INJECTOR_CHANNEL_HEADER_SIZE + INJECTOR_CHANNEL_RING_SIZE)
#define INJECTOR_PAYLOAD_MAX (16u * 1024u * 1024u)

/* Must stay in sync with Driver/Injection/KernelMapping/KernelMapping.h
   (INJECTOR_MAX_IMAGE).  The driver rejects anything larger, so the client
   refuses it up-front with a specific message instead of a generic one. */
#define INJECTOR_MAX_IMAGE 0x40000000UL

#define INJECTOR_MAX_SECTIONS       96
#define INJECTOR_MAX_TRIED_PATHS    96
#define INJECTOR_MAX_FORWARD_DEPTH  2
#define INJECTOR_MAX_EXPORT_NAMES   65536
#define INJECTOR_MAX_NAME_LEN       512

/*
 * The driver resolves a payload's imports against the modules that are
 * already loaded in the target process, so the client waits a settle period
 * before mapping.  Override with --settle <seconds>; 0 disables the wait.
 */
#define INJECTOR_DEFAULT_SETTLE_MS  10000

static int g_settleMs = INJECTOR_DEFAULT_SETTLE_MS;

#define INJECTOR_CMD_NONE     0
#define INJECTOR_CMD_VALIDATE 1
#define INJECTOR_CMD_MAP      2
#define INJECTOR_CMD_EXEC     3
#define INJECTOR_CMD_PROTECT_PID 4

typedef struct _INJECTOR_CHANNEL {
    unsigned long long Magic;
    unsigned int       AbiVersion;
    unsigned int       _pad0;
    volatile long      Head;
    volatile long      Tail;
    unsigned int       Pid;
    unsigned int       Flags;
    volatile long      Cmd;
    volatile long      Done;
    volatile long      CmdStatus;
    unsigned int       PayloadSize;
    unsigned int       PayloadReceived;
    unsigned int       _pad1;
    volatile unsigned long long RemoteBase;
    volatile unsigned long long RelocCount;
    volatile unsigned long long ImportDllCount;
    volatile long      TlsSlot;
    volatile long      TlsStatus;
    volatile long      TlsThreadsSeeded;
    unsigned char      _pad2[4];
    volatile unsigned long long ExecutionVa;
    volatile long      HijackThreadId;
    volatile long      HijackReserved;
    unsigned int       ProtectedPid;
    volatile long      ObCallbackStatus;
    volatile unsigned long long SelfTestAck;
    volatile unsigned long long GadgetVa;
    volatile long      ObInitStatus;
    unsigned int       _pad_obinit;
    unsigned char      Ring[INJECTOR_CHANNEL_RING_SIZE];
} INJECTOR_CHANNEL;

static_assert(offsetof(INJECTOR_CHANNEL, SelfTestAck) == 0x78,
              "Client SelfTestAck offset mismatch with driver");
static_assert(offsetof(INJECTOR_CHANNEL, ObInitStatus) == 0x88,
              "Client INJECTOR_CHANNEL.ObInitStatus offset mismatch with driver");
static_assert(offsetof(INJECTOR_CHANNEL, Ring) == 0x90,
              "Client INJECTOR_CHANNEL.Ring offset mismatch with driver");
static_assert(sizeof(INJECTOR_CHANNEL) >= 0x4090,
              "Client INJECTOR_CHANNEL must be at least 0x1000 header + 0x3000 ring");
static_assert(sizeof(INJECTOR_CHANNEL) == 0x90 + INJECTOR_CHANNEL_RING_SIZE,
              "Client INJECTOR_CHANNEL size mismatch with driver");
static_assert(sizeof(INJECTOR_CHANNEL) == 0x4090,
              "Client INJECTOR_CHANNEL must be exactly 0x4090 bytes");

template <size_t N> struct InjectorChannelSizeProof;
template <> struct InjectorChannelSizeProof<0x4090> { static constexpr bool ok = true; };
static InjectorChannelSizeProof<sizeof(INJECTOR_CHANNEL)> g_channelSizeProof;
static_assert(INJECTOR_CHANNEL_USER_VA == 0x00007FF000000000ULL,
              "Channel VA must not be overridden");
static_assert(INJECTOR_SELFTEST_ACK_OFFSET == offsetof(INJECTOR_CHANNEL, SelfTestAck),
              "INJECTOR_SELFTEST_ACK_OFFSET must match the struct offset");

/* ------------------------------------------------------------------ */
/* Console helpers                                                     */
/* ------------------------------------------------------------------ */

static void green_value(const char *fmt, ...)
{
    va_list ap;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO ci = { 0 };
    int colored = 0;

    va_start(ap, fmt);
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(hOut, &ci)) {
        SetConsoleTextAttribute(hOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        colored = 1;
    }
    vfprintf(stdout, fmt, ap);
    if (colored)
        SetConsoleTextAttribute(hOut, ci.wAttributes);
    va_end(ap);
}

static void blue_value(const char *fmt, ...)
{
    va_list ap;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO ci = { 0 };
    int colored = 0;

    va_start(ap, fmt);
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(hOut, &ci)) {
        SetConsoleTextAttribute(hOut, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        colored = 1;
    }
    vfprintf(stdout, fmt, ap);
    if (colored)
        SetConsoleTextAttribute(hOut, ci.wAttributes);
    va_end(ap);
}

static void print_channel_va(void)
{
    printf("  Channel's Virtual Address: ");
    green_value("0x%016llX", (unsigned long long)INJECTOR_CHANNEL_USER_VA);
    printf("\n");
}

static void wait_for_enter(void)
{
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;

    if (hIn == NULL || hIn == INVALID_HANDLE_VALUE) return;
    if (!GetConsoleMode(hIn, &mode)) return;
    (void)getchar();
}

static int stdin_is_console(void)
{
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;

    if (hIn == NULL || hIn == INVALID_HANDLE_VALUE) return 0;
    return GetConsoleMode(hIn, &mode) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Small string helpers                                                */
/* ------------------------------------------------------------------ */

static void trim_input(char *s)
{
    size_t len = strlen(s);
    size_t start = 0, end = len;

    while (start < end && (s[start] == ' ' || s[start] == '\t')) start++;
    while (end > start &&
           (s[end - 1] == ' ' || s[end - 1] == '\t' ||
            s[end - 1] == '\n' || s[end - 1] == '\r')) end--;
    if (start > 0 || end < len)
        memmove(s, s + start, end - start);
    s[end - start] = '\0';

    len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        s[len - 1] = '\0';
        memmove(s, s + 1, len);
    }
}

static void str_to_wide(const char *src, WCHAR *dst, size_t cap)
{
    size_t i = 0;

    while (src[i] != '\0' && i + 1 < cap) {
        dst[i] = (WCHAR)(UCHAR)src[i];
        i++;
    }
    dst[i] = L'\0';
}

static int wide_icmp(const WCHAR *a, const WCHAR *b)
{
    for (;;) {
        WCHAR ca = *a, cb = *b;

        if (ca >= L'A' && ca <= L'Z') ca = (WCHAR)(ca + 32);
        if (cb >= L'A' && cb <= L'Z') cb = (WCHAR)(cb + 32);
        if (ca != cb) return (int)(ca - cb);
        if (ca == '\0') return 0;
        a++;
        b++;
    }
}

static void join_path(char *dst, size_t cap, const char *dir, const char *name)
{
    size_t n;

    if (cap == 0) return;
    n = strlen(dir);
    if (n + 2 >= cap) { dst[0] = '\0'; return; }
    memcpy(dst, dir, n);
    if (n > 0 && dir[n - 1] != '\\' && dir[n - 1] != '/') {
        dst[n] = '\\';
        n++;
    }
    dst[n] = '\0';
    strncpy_s(dst + n, cap - n, name, _TRUNCATE);
}

static int file_exists(const char *path)
{
    DWORD attr;

    if (path == NULL || path[0] == '\0') return 0;
    attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return 0;
    if (attr & FILE_ATTRIBUTE_DIRECTORY) return 0;
    return 1;
}

static int dir_exists(const char *path)
{
    DWORD attr;

    if (path == NULL || path[0] == '\0') return 0;
    attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return 0;
    return (attr & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
}

/* Parse a hexadecimal RVA.  Accepts "0x1D10" and "1D10" (and "1d10"). */
static int parse_hex_u32(const char *s, DWORD *out)
{
    const char *p = s;
    unsigned long long v = 0;
    size_t i = 0;

    if (s == NULL || s[0] == '\0') return 0;
    while (s[i] == ' ' || s[i] == '\t') i++;
    p = s + i;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    if (p[0] == '\0') return 0;
    for (i = 0; p[i] != '\0'; i++) {
        char c = p[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return 0;
        v = (v << 4) | (unsigned)d;
        if (v > 0xFFFFFFFFULL) return 0;
    }
    *out = (DWORD)v;
    return 1;
}

/* ------------------------------------------------------------------ */
/* PE image model                                                      */
/* ------------------------------------------------------------------ */

typedef struct _INJECTOR_PE_SECTION {
    DWORD VirtualAddress;
    DWORD VirtualSize;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD Characteristics;
} INJECTOR_PE_SECTION;

typedef struct _INJECTOR_PE {
    unsigned char      *Buf;
    size_t              Len;
    DWORD               Lfanew;
    IMAGE_NT_HEADERS64  Nt;
    DWORD               NumberOfSections;
    INJECTOR_PE_SECTION Sections[INJECTOR_MAX_SECTIONS];

    BOOL                HasExportDir;
    DWORD               ExportDirRva;
    DWORD               ExportDirSize;
    DWORD               ExportDirRaw;
    DWORD               ExportBase;
    DWORD               NumberOfFunctions;
    DWORD               NumberOfNames;
    DWORD              *NameRvas;
    WORD               *NameOrdinals;
    DWORD              *FuncRvas;
    char                DllName[INJECTOR_MAX_NAME_LEN];
} INJECTOR_PE;

/* Frees the export tables.  The image buffer is owned by the caller. */
static void pe_free(INJECTOR_PE *pe)
{
    if (pe == NULL) return;
    if (pe->NameRvas != NULL) free(pe->NameRvas);
    if (pe->NameOrdinals != NULL) free(pe->NameOrdinals);
    if (pe->FuncRvas != NULL) free(pe->FuncRvas);
    pe->NameRvas = NULL;
    pe->NameOrdinals = NULL;
    pe->FuncRvas = NULL;
}

static int file_read_all(const char *path, unsigned char **out, size_t *outLen,
                         char *err, size_t errCap)
{
    HANDLE h;
    LARGE_INTEGER sz;
    unsigned char *buf;
    DWORD got = 0;

    *out = NULL;
    *outLen = 0;
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        snprintf(err, errCap, "cannot open %s (error %lu)",
                 path, (unsigned long)GetLastError());
        return 0;
    }
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0) {
        CloseHandle(h);
        snprintf(err, errCap, "cannot determine size of %s", path);
        return 0;
    }
    if (sz.QuadPart > (LONGLONG)INJECTOR_MAX_IMAGE) {
        CloseHandle(h);
        snprintf(err, errCap, "%s is %lld bytes; larger than the 0x%X byte limit",
                 path, (long long)sz.QuadPart, INJECTOR_MAX_IMAGE);
        return 0;
    }
    buf = (unsigned char *)malloc((size_t)sz.QuadPart);
    if (buf == NULL) {
        CloseHandle(h);
        snprintf(err, errCap, "out of memory reading %s", path);
        return 0;
    }
    if (!ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart) {
        free(buf);
        CloseHandle(h);
        snprintf(err, errCap, "short read on %s", path);
        return 0;
    }
    CloseHandle(h);
    *out = buf;
    *outLen = (size_t)sz.QuadPart;
    return 1;
}

/*
 * Validate the DOS header, NT headers, machine type, optional-header magic
 * and SizeOfImage.  Every rejection carries a specific message; the caller
 * never has to fall back to a generic "export not found".
 *
 * The image buffer is NOT owned by the PE model; the caller keeps it and may
 * hand the very same bytes to the driver, so the bytes that were validated
 * are exactly the bytes that get injected.
 */
static int pe_parse_buffer(unsigned char *buf, size_t len, INJECTOR_PE *pe,
                            char *err, size_t errCap)
{
    IMAGE_DOS_HEADER dos;
    WORD magic = 0;
    DWORD secOff = 0;
    DWORD i = 0;

    memset(pe, 0, sizeof(*pe));
    pe->Buf = buf;
    pe->Len = len;

    if (len < sizeof(IMAGE_DOS_HEADER)) {
        snprintf(err, errCap,
                 "file is only %zu bytes; too small to be a PE image", len);
        pe_free(pe);
        return 0;
    }

    memcpy(&dos, buf, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        snprintf(err, errCap,
                 "not a PE file: DOS signature 0x%04X (expected 0x5A4D 'MZ')",
                 (unsigned)dos.e_magic);
        pe_free(pe);
        return 0;
    }

    pe->Lfanew = (DWORD)dos.e_lfanew;
    if (dos.e_lfanew < 0 ||
        (size_t)pe->Lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD) > len) {
        snprintf(err, errCap,
                 "corrupt PE: e_lfanew 0x%X points past end of file (%zu bytes)",
                 (unsigned)pe->Lfanew, len);
        pe_free(pe);
        return 0;
    }

    memcpy(&magic, buf + pe->Lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER),
           sizeof(magic));
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        snprintf(err, errCap,
                 "32-bit DLL cannot be injected into a 64-bit target "
                 "(optional header magic 0x%03X IMAGE_NT_OPTIONAL_HDR32_MAGIC)",
                 (unsigned)magic);
        pe_free(pe);
        return 0;
    }
    if (magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        snprintf(err, errCap,
                 "corrupt PE: optional header magic 0x%03X "
                 "(expected 0x%03X IMAGE_NT_OPTIONAL_HDR64_MAGIC)",
                 (unsigned)magic, (unsigned)IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        pe_free(pe);
        return 0;
    }

    if ((size_t)pe->Lfanew + sizeof(IMAGE_NT_HEADERS64) > len) {
        snprintf(err, errCap,
                 "corrupt PE: truncated NT headers at e_lfanew 0x%X "
                 "(file is %zu bytes)", (unsigned)pe->Lfanew, len);
        pe_free(pe);
        return 0;
    }

    memcpy(&pe->Nt, buf + pe->Lfanew, sizeof(IMAGE_NT_HEADERS64));

    if (pe->Nt.Signature != IMAGE_NT_SIGNATURE) {
        snprintf(err, errCap,
                 "corrupt PE: NT signature 0x%08X (expected 0x%08X 'PE\\0\\0')",
                 (unsigned)pe->Nt.Signature, (unsigned)IMAGE_NT_SIGNATURE);
        pe_free(pe);
        return 0;
    }

    switch (pe->Nt.FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_AMD64:
        break;
    case IMAGE_FILE_MACHINE_I386:
        snprintf(err, errCap,
                 "32-bit DLL cannot be injected into a 64-bit target "
                 "(machine 0x%04X IMAGE_FILE_MACHINE_I386)",
                 (unsigned)pe->Nt.FileHeader.Machine);
        pe_free(pe);
        return 0;
    case IMAGE_FILE_MACHINE_ARM64:
        snprintf(err, errCap,
                 "architecture mismatch: ARM64 DLL cannot be injected into an "
                 "x64 target (machine 0x%04X IMAGE_FILE_MACHINE_ARM64)",
                 (unsigned)pe->Nt.FileHeader.Machine);
        pe_free(pe);
        return 0;
    default:
        snprintf(err, errCap,
                 "unsupported machine type 0x%04X "
                 "(expected 0x%04X IMAGE_FILE_MACHINE_AMD64)",
                 (unsigned)pe->Nt.FileHeader.Machine,
                 (unsigned)IMAGE_FILE_MACHINE_AMD64);
        pe_free(pe);
        return 0;
    }

    if (pe->Nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        snprintf(err, errCap,
                 "architecture mismatch: machine 0x%04X but optional header "
                 "magic 0x%03X",
                 (unsigned)pe->Nt.FileHeader.Machine,
                 (unsigned)pe->Nt.OptionalHeader.Magic);
        pe_free(pe);
        return 0;
    }

    if (pe->Nt.OptionalHeader.SizeOfImage == 0 ||
        pe->Nt.OptionalHeader.SizeOfImage > INJECTOR_MAX_IMAGE) {
        snprintf(err, errCap,
                 "invalid SizeOfImage 0x%X (must be non-zero and <= 0x%X, "
                 "the driver's INJECTOR_MAX_IMAGE)",
                 (unsigned)pe->Nt.OptionalHeader.SizeOfImage,
                 (unsigned)INJECTOR_MAX_IMAGE);
        pe_free(pe);
        return 0;
    }

    pe->NumberOfSections = (DWORD)pe->Nt.FileHeader.NumberOfSections;
    if (pe->NumberOfSections == 0 || pe->NumberOfSections > INJECTOR_MAX_SECTIONS) {
        snprintf(err, errCap, "invalid section count %u (must be 1..%u)",
                 (unsigned)pe->NumberOfSections, (unsigned)INJECTOR_MAX_SECTIONS);
        pe_free(pe);
        return 0;
    }

    secOff = pe->Lfanew + (DWORD)sizeof(DWORD) + (DWORD)sizeof(IMAGE_FILE_HEADER) +
             (DWORD)pe->Nt.FileHeader.SizeOfOptionalHeader;
    if ((size_t)secOff + (size_t)pe->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > len) {
        snprintf(err, errCap, "corrupt PE: section table runs past end of file");
        pe_free(pe);
        return 0;
    }

    for (i = 0; i < pe->NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sh;
        memcpy(&sh, buf + secOff + i * sizeof(IMAGE_SECTION_HEADER), sizeof(sh));
        pe->Sections[i].VirtualAddress = sh.VirtualAddress;
        pe->Sections[i].VirtualSize = sh.Misc.VirtualSize;
        pe->Sections[i].SizeOfRawData = sh.SizeOfRawData;
        pe->Sections[i].PointerToRawData = sh.PointerToRawData;
        pe->Sections[i].Characteristics = sh.Characteristics;
    }

    return 1;
}

/* Load a file and parse it.  On success the caller owns pe->Buf. */
static int pe_load(const char *path, INJECTOR_PE *pe, char *err, size_t errCap)
{
    unsigned char *buf = NULL;
    size_t len = 0;

    memset(pe, 0, sizeof(*pe));
    if (!file_read_all(path, &buf, &len, err, errCap))
        return 0;
    if (!pe_parse_buffer(buf, len, pe, err, errCap)) {
        free(buf);
        return 0;
    }
    return 1;
}

static int pe_rva_to_raw(const INJECTOR_PE *pe, DWORD rva, DWORD *out)
{
    DWORD i;

    if (rva < pe->Nt.OptionalHeader.SizeOfHeaders) {
        if ((size_t)rva < pe->Len) { *out = rva; return 1; }
        return 0;
    }

    for (i = 0; i < pe->NumberOfSections; i++) {
        const INJECTOR_PE_SECTION *s = &pe->Sections[i];
        DWORD span = s->VirtualSize ? s->VirtualSize : s->SizeOfRawData;
        DWORD delta;

        if (span < s->SizeOfRawData) span = s->SizeOfRawData;
        if (rva < s->VirtualAddress) continue;
        delta = rva - s->VirtualAddress;
        if (delta >= span) continue;
        if (delta >= s->SizeOfRawData) return 0;
        if ((size_t)s->PointerToRawData + delta >= pe->Len) return 0;
        *out = s->PointerToRawData + delta;
        return 1;
    }
    return 0;
}

static int pe_parse_exports(INJECTOR_PE *pe)
{
    IMAGE_DATA_DIRECTORY dd;
    IMAGE_EXPORT_DIRECTORY exp;
    DWORD raw = 0;

    if (pe->Nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return 1;
    dd = pe->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dd.VirtualAddress == 0 || dd.Size == 0)
        return 1;

    pe->ExportDirRva = dd.VirtualAddress;
    pe->ExportDirSize = dd.Size;

    if (!pe_rva_to_raw(pe, pe->ExportDirRva, &raw)) return 1;
    if ((size_t)raw + sizeof(IMAGE_EXPORT_DIRECTORY) > pe->Len) return 1;

    memcpy(&exp, pe->Buf + raw, sizeof(exp));
    pe->ExportDirRaw = raw;
    pe->ExportBase = exp.Base;
    pe->NumberOfFunctions = exp.NumberOfFunctions;
    pe->NumberOfNames = exp.NumberOfNames;
    pe->HasExportDir = TRUE;

    if (exp.Name != 0) {
        DWORD nraw = 0;
        if (pe_rva_to_raw(pe, exp.Name, &nraw)) {
            size_t k = 0;
            while (nraw + k < pe->Len && pe->Buf[nraw + k] != '\0' &&
                   k + 1 < sizeof(pe->DllName)) {
                pe->DllName[k] = (char)pe->Buf[nraw + k];
                k++;
            }
            pe->DllName[k] = '\0';
        }
    }

    if (pe->NumberOfFunctions > INJECTOR_MAX_EXPORT_NAMES) {
        pe->NumberOfFunctions = 0;
        return 1;
    }
    if (pe->NumberOfNames > INJECTOR_MAX_EXPORT_NAMES) {
        pe->NumberOfNames = 0;
        return 1;
    }

    if (pe->NumberOfFunctions > 0) {
        DWORD fraw = 0;
        if (!pe_rva_to_raw(pe, exp.AddressOfFunctions, &fraw)) {
            pe->NumberOfFunctions = 0;
        } else if ((size_t)fraw + (size_t)pe->NumberOfFunctions * sizeof(DWORD) > pe->Len) {
            pe->NumberOfFunctions = 0;
        } else {
            pe->FuncRvas = (DWORD *)malloc((size_t)pe->NumberOfFunctions * sizeof(DWORD));
            if (pe->FuncRvas == NULL) {
                pe->NumberOfFunctions = 0;
            } else {
                memcpy(pe->FuncRvas, pe->Buf + fraw,
                       (size_t)pe->NumberOfFunctions * sizeof(DWORD));
            }
        }
    }

    if (pe->NumberOfNames > 0) {
        DWORD nraw = 0, oraw = 0;
        if (!pe_rva_to_raw(pe, exp.AddressOfNames, &nraw) ||
            !pe_rva_to_raw(pe, exp.AddressOfNameOrdinals, &oraw)) {
            pe->NumberOfNames = 0;
        } else if ((size_t)nraw + (size_t)pe->NumberOfNames * sizeof(DWORD) > pe->Len ||
                   (size_t)oraw + (size_t)pe->NumberOfNames * sizeof(WORD) > pe->Len) {
            pe->NumberOfNames = 0;
        } else {
            pe->NameRvas = (DWORD *)malloc((size_t)pe->NumberOfNames * sizeof(DWORD));
            pe->NameOrdinals = (WORD *)malloc((size_t)pe->NumberOfNames * sizeof(WORD));
            if (pe->NameRvas == NULL || pe->NameOrdinals == NULL) {
                pe->NumberOfNames = 0;
            } else {
                memcpy(pe->NameRvas, pe->Buf + nraw,
                       (size_t)pe->NumberOfNames * sizeof(DWORD));
                memcpy(pe->NameOrdinals, pe->Buf + oraw,
                       (size_t)pe->NumberOfNames * sizeof(WORD));
            }
        }
    }

    return 1;
}

static const char *pe_export_name(const INJECTOR_PE *pe, DWORD nameIndex,
                                  char *buf, size_t cap)
{
    DWORD raw = 0;
    size_t k = 0;

    if (nameIndex >= pe->NumberOfNames) return NULL;
    if (!pe_rva_to_raw(pe, pe->NameRvas[nameIndex], &raw)) return NULL;
    while (raw + k < pe->Len && pe->Buf[raw + k] != '\0' && k + 1 < cap) {
        buf[k] = (char)pe->Buf[raw + k];
        k++;
    }
    buf[k] = '\0';
    if (k == 0) return NULL;
    return buf;
}

/* Resolve a named export to its RVA.  caseSensitive selects exact vs
   case-insensitive matching. */
static int pe_find_export(const INJECTOR_PE *pe, const char *name, int caseSensitive,
                           DWORD *outRva, DWORD *outNameIndex)
{
    DWORD i;
    char tmp[INJECTOR_MAX_NAME_LEN];

    for (i = 0; i < pe->NumberOfNames; i++) {
        const char *n = pe_export_name(pe, i, tmp, sizeof(tmp));
        int hit;

        if (n == NULL) continue;
        hit = caseSensitive ? (strcmp(n, name) == 0) : (_stricmp(n, name) == 0);
        if (!hit) continue;
        if (pe->NameOrdinals[i] >= pe->NumberOfFunctions) return 0;
        if (outRva != NULL) *outRva = pe->FuncRvas[pe->NameOrdinals[i]];
        if (outNameIndex != NULL) *outNameIndex = i;
        return 1;
    }
    return 0;
}

/* A C++-mangled ManualEntry looks like "?ManualEntry@@YAHPEAUHINSTANCE__@@@Z";
   they all contain the "ManualEntry@@" marker. */
static int name_is_mangled_manualentry(const char *n)
{
    return (strstr(n, "ManualEntry@@") != NULL) ? 1 : 0;
}

static const char *g_wellKnownNames[] = {
    "ManualEntry",
    "EntryPoint",
    "DirectEntry",
    "DllMain",
    "ReflectiveLoader",
    "Load",
    "Init"
};
#define INJECTOR_WELL_KNOWN_COUNT \
    (sizeof(g_wellKnownNames) / sizeof(g_wellKnownNames[0]))

static const char *g_mangledNames[] = {
    "?ManualEntry@@YAHPEAUHINSTANCE__@@@Z",
    "?ManualEntry@@YAXXZ",
    "?ManualEntry@@YAHXZ"
};
#define INJECTOR_MANGLED_COUNT \
    (sizeof(g_mangledNames) / sizeof(g_mangledNames[0]))

/* ------------------------------------------------------------------ */
/* Export diagnostics                                                  */
/* ------------------------------------------------------------------ */

static const char *pe_arch_text(const INJECTOR_PE *pe)
{
    switch (pe->Nt.FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_AMD64:
        return "PE32+ x64 (IMAGE_FILE_MACHINE_AMD64)";
    case IMAGE_FILE_MACHINE_I386:
        return "PE32 x86 (IMAGE_FILE_MACHINE_I386)";
    case IMAGE_FILE_MACHINE_ARM64:
        return "PE32+ ARM64 (IMAGE_FILE_MACHINE_ARM64)";
    default:
        return "unknown machine type";
    }
}

static void pe_print_tried_names(void)
{
    size_t i;

    printf("  Tried names: ");
    for (i = 0; i < INJECTOR_WELL_KNOWN_COUNT; i++) {
        if (i != 0) printf(", ");
        printf("%s", g_wellKnownNames[i]);
    }
    printf("\n");
    printf("  Tried mangled: ");
    for (i = 0; i < INJECTOR_MANGLED_COUNT; i++) {
        if (i != 0) printf(", ");
        printf("%s", g_mangledNames[i]);
    }
    printf(" (any export containing \"ManualEntry@@\")\n");
}

/* Full export-table dump: this is what lets the operator pick the right
   export when auto-discovery cannot. */
static void pe_dump_exports(const INJECTOR_PE *pe, const char *path)
{
    DWORD i;
    DWORD namedShown = 0;
    DWORD ordinalOnly = 0;
    char tmp[INJECTOR_MAX_NAME_LEN];
    char ordinalBuf[1024];
    size_t ob = 0;

    printf("FAIL: no acceptable export in %s\n", path);
    printf("  Arch: %s\n", pe_arch_text(pe));
    printf("  Optional header magic: 0x%03X   SizeOfImage: 0x%X   Sections: %u\n",
           (unsigned)pe->Nt.OptionalHeader.Magic,
           (unsigned)pe->Nt.OptionalHeader.SizeOfImage,
           (unsigned)pe->NumberOfSections);
    if (pe->HasExportDir) {
        printf("  Export directory: present (RVA=0x%X size=0x%X)\n",
               (unsigned)pe->ExportDirRva, (unsigned)pe->ExportDirSize);
        if (pe->DllName[0] != '\0')
            printf("  DLL name: %s\n", pe->DllName);
    } else {
        printf("  Export directory: absent\n");
    }

    printf("  Named exports (%u):\n", (unsigned)pe->NumberOfNames);
    for (i = 0; i < pe->NumberOfNames; i++) {
        const char *n = pe_export_name(pe, i, tmp, sizeof(tmp));
        DWORD rva = 0;
        const char *mark = "";

        if (n == NULL) continue;
        if (pe->NameOrdinals[i] < pe->NumberOfFunctions)
            rva = pe->FuncRvas[pe->NameOrdinals[i]];
        if (pe->HasExportDir && rva >= pe->ExportDirRva &&
            rva < pe->ExportDirRva + pe->ExportDirSize)
            mark = "  (forwarded)";
        printf("    %s  RVA=0x%X  ord=%u%s\n", n, (unsigned)rva,
               (unsigned)(pe->ExportBase + pe->NameOrdinals[i]), mark);
        namedShown++;
    }
    if (namedShown == 0)
        printf("    (none)\n");

    ordinalBuf[0] = '\0';
    for (i = 0; i < pe->NumberOfFunctions; i++) {
        BOOL isNamed = FALSE;
        DWORD j;

        if (pe->FuncRvas[i] == 0) continue;
        for (j = 0; j < pe->NumberOfNames; j++) {
            if (pe->NameOrdinals[j] == (WORD)i) { isNamed = TRUE; break; }
        }
        if (isNamed) continue;
        if (ob + 16 < sizeof(ordinalBuf)) {
            ob += (size_t)snprintf(ordinalBuf + ob, sizeof(ordinalBuf) - ob,
                                    "%s0x%X", ob ? ", " : "",
                                    (unsigned)pe->FuncRvas[i]);
        }
        ordinalOnly++;
    }
    if (ordinalOnly > 0)
        printf("  Ordinal-only exports (%u): %s\n",
               (unsigned)ordinalOnly, ordinalBuf);
    else
        printf("  Ordinal-only exports (0): none\n");

    pe_print_tried_names();
    printf("Hint: pass --export <name> or --rva <hex> to override.\n");
}

/* ------------------------------------------------------------------ */
/* Forwarded export resolution                                         */
/* ------------------------------------------------------------------ */

static int pe_is_forwarded(const INJECTOR_PE *pe, DWORD rva)
{
    if (!pe->HasExportDir) return 0;
    if (rva == 0) return 0;
    return (rva >= pe->ExportDirRva &&
            rva < pe->ExportDirRva + pe->ExportDirSize) ? 1 : 0;
}

static int pe_forwarder_string(const INJECTOR_PE *pe, DWORD rva,
                                char *out, size_t cap)
{
    DWORD raw = 0;
    size_t k = 0;

    if (!pe_rva_to_raw(pe, rva, &raw)) return 0;
    while (raw + k < pe->Len && pe->Buf[raw + k] != '\0' && k + 1 < cap) {
        out[k] = (char)pe->Buf[raw + k];
        k++;
    }
    out[k] = '\0';
    return (k > 0) ? 1 : 0;
}

static int module_basename_match(const char *fullPath, const char *moduleName)
{
    const char *base = fullPath;
    const char *p;
    size_t bl, ml;

    for (p = fullPath; *p != '\0'; p++) {
        if (*p == '\\' || *p == '/') base = p + 1;
    }
    bl = strlen(base);
    ml = strlen(moduleName);
    if (bl >= 4 && _stricmp(base + bl - 4, ".dll") == 0) bl -= 4;
    if (ml >= 4 && _stricmp(moduleName + ml - 4, ".dll") == 0) ml -= 4;
    if (bl != ml) return 0;
    return (_strnicmp(base, moduleName, ml) == 0) ? 1 : 0;
}

/* Wide variant: the toolhelp module snapshot is the Unicode flavour in this
   build, so the comparison has to be done on WCHAR as well. */
static int module_basename_match_w(const WCHAR *fullPath, const char *moduleName)
{
    const WCHAR *base = fullPath;
    const WCHAR *p;
    WCHAR want[MAX_PATH];
    size_t bl, wl;
    size_t i;

    for (p = fullPath; *p != L'\0'; p++) {
        if (*p == L'\\' || *p == L'/') base = p + 1;
    }
    str_to_wide(moduleName, want, MAX_PATH);

    bl = 0;
    while (base[bl] != L'\0') bl++;
    wl = 0;
    while (want[wl] != L'\0') wl++;

    if (bl >= 4 && wide_icmp(base + bl - 4, L".dll") == 0) bl -= 4;
    if (wl >= 4 && wide_icmp(want + wl - 4, L".dll") == 0) wl -= 4;
    if (bl != wl) return 0;

    for (i = 0; i < bl; i++) {
        if (wide_icmp(base + i, want + i) != 0) return 0;
    }
    return 1;
}

/* Find the base address of a module as mapped in the target process.
   Uses a module snapshot, which does not require an OpenProcess handle and
   therefore still works after the driver arms its ObCallback protection. */
static BOOL find_target_module_base(DWORD pid, const char *moduleName,
                                     unsigned long long *outBase)
{
    HANDLE snap;
    MODULEENTRY32 me;
    BOOL found = FALSE;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            if (module_basename_match_w(me.szExePath, moduleName) ||
                module_basename_match_w(me.szModule, moduleName)) {
                *outBase = (unsigned long long)(ULONG_PTR)me.modBaseAddr;
                found = TRUE;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

/* Resolve "<module>.<symbol>" or "<module>.#<ordinal>" inside one of the
   system DLLs the driver-side forwarder may point at.  The system images are
   identical across processes, so the RVA is the same in the target. */
static int resolve_system_export(const char *module, const char *symbol,
                                 DWORD *outRva, char *err, size_t errCap)
{
    /* Forwarder strings conventionally omit the ".dll" extension
       ("KERNEL32.Sleep"), so compare on the bare module name. */
    static const char *kAllowed[] = { "ntdll", "kernel32", "kernelbase" };
    size_t i;
    size_t mlen = strlen(module);
    HMODULE h;
    FARPROC proc;

    if (mlen >= 4 && _stricmp(module + mlen - 4, ".dll") == 0) mlen -= 4;

    for (i = 0; i < sizeof(kAllowed) / sizeof(kAllowed[0]); i++) {
        if (strlen(kAllowed[i]) == mlen &&
            _strnicmp(module, kAllowed[i], mlen) == 0) break;
    }
    if (i == sizeof(kAllowed) / sizeof(kAllowed[0])) {
        snprintf(err, errCap,
                 "forwarded export points at module '%s'; only ntdll, kernel32 "
                 "and kernelbase can be resolved", module);
        return 0;
    }

    h = GetModuleHandleA(module);
    if (h == NULL) h = LoadLibraryA(module);
    if (h == NULL) {
        snprintf(err, errCap, "module '%s' is not loaded in the client", module);
        return 0;
    }

    if (symbol[0] == '#') {
        /* Ordinal export: walk the module's own export table on disk. */
        char path[MAX_PATH];
        INJECTOR_PE pe;
        char e[512];
        DWORD want = 0;
        BOOL ok = FALSE;

        if (!parse_hex_u32(symbol + 1, &want)) {
            snprintf(err, errCap, "malformed forwarder ordinal '%s'", symbol);
            return 0;
        }
        if (!GetModuleFileNameA(h, path, (DWORD)sizeof(path))) {
            snprintf(err, errCap, "cannot locate '%s' on disk", module);
            return 0;
        }
        if (!pe_load(path, &pe, e, sizeof(e))) {
            snprintf(err, errCap, "%s", e);
            return 0;
        }
        pe_parse_exports(&pe);
        for (i = 0; i < pe.NumberOfFunctions; i++) {
            if (pe.ExportBase + i == want) {
                *outRva = pe.FuncRvas[i];
                ok = TRUE;
                break;
            }
        }
        pe_free(&pe);
        if (pe.Buf != NULL) free(pe.Buf);
        if (!ok) {
            snprintf(err, errCap, "ordinal %u not found in %s", (unsigned)want, module);
            return 0;
        }
        return 1;
    }

    proc = GetProcAddress(h, symbol);
    if (proc == NULL) {
        snprintf(err, errCap, "symbol '%s' not found in %s", symbol, module);
        return 0;
    }
    *outRva = (DWORD)((const unsigned char *)proc - (const unsigned char *)h);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Adaptive export discovery                                           */
/* ------------------------------------------------------------------ */

typedef struct _EXPORT_CHOICE {
    DWORD rva;
    char  name[INJECTOR_MAX_NAME_LEN];
    char  origin[64];
    BOOL  forwarded;
} EXPORT_CHOICE;

/*
 * Priority:
 *   1. explicit --export <name>
 *   2. explicit --rva <hex>
 *   3. well-known names (exact pass, then case-insensitive pass)
 *   4. C++-mangled ManualEntry
 *   5. first named export
 *   6. first function (ordinal-only DLL)
 */
static int discover_export(const INJECTOR_PE *pe, const char *explicitName,
                           BOOL haveRva, DWORD explicitRva,
                           EXPORT_CHOICE *out, char *err, size_t errCap)
{
    DWORD rva = 0;
    DWORD idx = 0;
    DWORD i;
    char tmp[INJECTOR_MAX_NAME_LEN];

    memset(out, 0, sizeof(*out));

    if (explicitName != NULL && explicitName[0] != '\0') {
        if (!pe_find_export(pe, explicitName, 1, &rva, &idx) &&
            !pe_find_export(pe, explicitName, 0, &rva, &idx)) {
            snprintf(err, errCap, "export '%s' not found", explicitName);
            return 0;
        }
        out->rva = rva;
        lstrcpynA(out->name, explicitName, (int)sizeof(out->name));
        lstrcpynA(out->origin, "explicit --export", (int)sizeof(out->origin));
        out->forwarded = pe_is_forwarded(pe, rva);
        return 1;
    }

    if (haveRva) {
        if (explicitRva == 0) {
            snprintf(err, errCap, "RVA 0x0 is not a valid entry point");
            return 0;
        }
        if (explicitRva >= pe->Nt.OptionalHeader.SizeOfImage) {
            snprintf(err, errCap,
                     "RVA 0x%X is outside the image (SizeOfImage 0x%X)",
                     (unsigned)explicitRva,
                     (unsigned)pe->Nt.OptionalHeader.SizeOfImage);
            return 0;
        }
        out->rva = explicitRva;
        snprintf(out->name, sizeof(out->name), "<explicit rva 0x%X>",
                 (unsigned)explicitRva);
        lstrcpynA(out->origin, "explicit --rva", (int)sizeof(out->origin));
        out->forwarded = pe_is_forwarded(pe, explicitRva);
        return 1;
    }

    /* 3. well-known names - exact match pass first */
    for (i = 0; i < INJECTOR_WELL_KNOWN_COUNT; i++) {
        if (pe_find_export(pe, g_wellKnownNames[i], 1, &rva, &idx)) {
            out->rva = rva;
            lstrcpynA(out->name, g_wellKnownNames[i], (int)sizeof(out->name));
            lstrcpynA(out->origin, "well-known name", (int)sizeof(out->origin));
            out->forwarded = pe_is_forwarded(pe, rva);
            return 1;
        }
    }
    /* 3b. well-known names - case-insensitive pass */
    for (i = 0; i < INJECTOR_WELL_KNOWN_COUNT; i++) {
        if (pe_find_export(pe, g_wellKnownNames[i], 0, &rva, &idx)) {
            out->rva = rva;
            lstrcpynA(out->name, g_wellKnownNames[i], (int)sizeof(out->name));
            lstrcpynA(out->origin, "well-known name (case-insensitive)",
                      (int)sizeof(out->origin));
            out->forwarded = pe_is_forwarded(pe, rva);
            return 1;
        }
    }

    /* 4. C++-mangled ManualEntry */
    for (i = 0; i < INJECTOR_MANGLED_COUNT; i++) {
        if (pe_find_export(pe, g_mangledNames[i], 1, &rva, &idx) ||
            pe_find_export(pe, g_mangledNames[i], 0, &rva, &idx)) {
            const char *n = pe_export_name(pe, idx, tmp, sizeof(tmp));
            out->rva = rva;
            lstrcpynA(out->name, n ? n : g_mangledNames[i], (int)sizeof(out->name));
            lstrcpynA(out->origin, "mangled name", (int)sizeof(out->origin));
            out->forwarded = pe_is_forwarded(pe, rva);
            return 1;
        }
    }
    for (i = 0; i < pe->NumberOfNames; i++) {
        const char *n = pe_export_name(pe, i, tmp, sizeof(tmp));
        if (n == NULL) continue;
        if (!name_is_mangled_manualentry(n)) continue;
        if (pe->NameOrdinals[i] >= pe->NumberOfFunctions) continue;
        rva = pe->FuncRvas[pe->NameOrdinals[i]];
        out->rva = rva;
        lstrcpynA(out->name, n, (int)sizeof(out->name));
        lstrcpynA(out->origin, "mangled name", (int)sizeof(out->origin));
        out->forwarded = pe_is_forwarded(pe, rva);
        return 1;
    }

    /* 5. first named export */
    for (i = 0; i < pe->NumberOfNames; i++) {
        const char *n = pe_export_name(pe, i, tmp, sizeof(tmp));
        if (n == NULL) continue;
        if (pe->NameOrdinals[i] >= pe->NumberOfFunctions) continue;
        rva = pe->FuncRvas[pe->NameOrdinals[i]];
        out->rva = rva;
        lstrcpynA(out->name, n, (int)sizeof(out->name));
        lstrcpynA(out->origin, "first named export", (int)sizeof(out->origin));
        out->forwarded = pe_is_forwarded(pe, rva);
        return 1;
    }

    /* 6. first function (ordinal-only DLL) */
    for (i = 0; i < pe->NumberOfFunctions; i++) {
        if (pe->FuncRvas[i] == 0) continue;
        out->rva = pe->FuncRvas[i];
        snprintf(out->name, sizeof(out->name), "<ordinal %u>",
                 (unsigned)(pe->ExportBase + i));
        lstrcpynA(out->origin, "first function", (int)sizeof(out->origin));
        out->forwarded = pe_is_forwarded(pe, out->rva);
        return 1;
    }

    if (!pe->HasExportDir)
        snprintf(err, errCap, "the image has no export directory");
    else if (pe->NumberOfNames == 0 && pe->NumberOfFunctions == 0)
        snprintf(err, errCap, "the export directory is empty");
    else
        snprintf(err, errCap, "the image exports no code");
    return 0;
}

/* ------------------------------------------------------------------ */
/* DLL path resolution                                                 */
/* ------------------------------------------------------------------ */

typedef struct _PATH_TRIALS {
    char paths[INJECTOR_MAX_TRIED_PATHS][MAX_PATH];
    int  count;
    char ambiguous[1024];
} PATH_TRIALS;

static void trial_record(PATH_TRIALS *t, const char *path)
{
    if (t->count >= INJECTOR_MAX_TRIED_PATHS) return;
    lstrcpynA(t->paths[t->count], path, MAX_PATH);
    t->count++;
}

/* Records the path and reports whether the file exists. */
static int trial_check(PATH_TRIALS *t, const char *path)
{
    trial_record(t, path);
    return file_exists(path);
}

static void list_dlls_in(const char *dir, char *out, size_t cap)
{
    WIN32_FIND_DATAA fd;
    char pattern[MAX_PATH];
    HANDLE h;
    size_t used = 0;

    out[0] = '\0';
    join_path(pattern, sizeof(pattern), dir, "*.dll");
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        lstrcpynA(out, "(none)", (int)cap);
        return;
    }
    do {
        if (fd.cFileName[0] == '.') continue;
        if (used + strlen(fd.cFileName) + 3 >= cap) break;
        if (used != 0) { out[used++] = ','; out[used++] = ' '; }
        lstrcpynA(out + used, fd.cFileName, (int)(cap - used));
        used += strlen(out + used);
    } while (FindNextFileA(h, &fd));
    CloseHandle(h);
    if (out[0] == '\0') lstrcpynA(out, "(none)", (int)cap);
}

static int find_cwd_single_dll(PATH_TRIALS *t, char *out, size_t cap)
{
    WIN32_FIND_DATAA fd;
    char pattern[MAX_PATH];
    char cwd[MAX_PATH];
    HANDLE h;
    char found[MAX_PATH];
    int count = 0;

    found[0] = '\0';
    GetCurrentDirectoryA((DWORD)sizeof(cwd), cwd);
    join_path(pattern, sizeof(pattern), cwd, "*.dll");

    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.cFileName[0] == '.') continue;
        if (count == 0) lstrcpynA(found, fd.cFileName, MAX_PATH);
        count++;
        if (count > 1) break;
    } while (FindNextFileA(h, &fd));
    CloseHandle(h);

    if (count == 0) return 0;
    if (count == 1) {
        char full[MAX_PATH];
        join_path(full, sizeof(full), cwd, found);
        if (trial_check(t, full)) {
            lstrcpynA(out, full, (int)cap);
            return 1;
        }
        return 0;
    }

    /* More than one DLL in the working directory: ambiguous. */
    {
        char names[1024];
        char pattern2[MAX_PATH];
        HANDLE h2;
        size_t used = 0;

        join_path(pattern2, sizeof(pattern2), cwd, "*.dll");
        names[0] = '\0';
        h2 = FindFirstFileA(pattern2, &fd);
        if (h2 != INVALID_HANDLE_VALUE) {
            do {
                if (fd.cFileName[0] == '.') continue;
                if (used + strlen(fd.cFileName) + 3 >= sizeof(names)) break;
                if (used != 0) { names[used++] = ','; names[used++] = ' '; }
                lstrcpynA(names + used, fd.cFileName, (int)(sizeof(names) - used));
                used += strlen(names + used);
            } while (FindNextFileA(h2, &fd));
            CloseHandle(h2);
        }
        lstrcpynA(t->ambiguous, names, (int)sizeof(t->ambiguous));
        printf("  NOTE: the working directory holds %d DLLs (%s); the search "
               "continues, pass --dll <path> to pick one explicitly.\n",
               count, names);
    }
    return 0;
}

/* Find <root>\Assets\DLL\... by walking up from the client directory. */
static int find_assets_dll(const char *clientDir, const char *leaf,
                           char *out, size_t cap, PATH_TRIALS *t)
{
    char cur[MAX_PATH];
    char probe[MAX_PATH];
    char cand[MAX_PATH];
    int depth = 0;

    lstrcpynA(cur, clientDir, MAX_PATH);
    while (cur[0] != '\0' && depth < 16) {
        char *slash;

        join_path(probe, sizeof(probe), cur, "Assets");
        if (dir_exists(probe)) {
            char assetsDir[MAX_PATH];
            char dllDir[MAX_PATH];
            lstrcpynA(assetsDir, probe, MAX_PATH);
            join_path(dllDir, sizeof(dllDir), assetsDir, "DLL");
            join_path(cand, sizeof(cand), dllDir, leaf);
            if (trial_check(t, cand)) {
                lstrcpynA(out, cand, (int)cap);
                return 1;
            }
        }
        slash = strrchr(cur, '\\');
        if (slash == NULL) break;
        if (slash == cur) break;
        *slash = '\0';
        depth++;
    }
    return 0;
}

/* Single-level recursive search for <root>\Target.dll. */
static int find_target_under_root(const char *root, char *out, size_t cap,
                                  PATH_TRIALS *t)
{
    WIN32_FIND_DATAA fd;
    char pattern[MAX_PATH];
    char cand[MAX_PATH];
    char sub[MAX_PATH];
    HANDLE h;

    join_path(pattern, sizeof(pattern), root, "*Target.dll");
    h = FindFirstFileA(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (fd.cFileName[0] == '.') continue;
            join_path(cand, sizeof(cand), root, fd.cFileName);
            if (trial_check(t, cand)) {
                lstrcpynA(out, cand, (int)cap);
                CloseHandle(h);
                return 1;
            }
        } while (FindNextFileA(h, &fd));
        CloseHandle(h);
    }

    join_path(pattern, sizeof(pattern), root, "*");
    h = FindFirstFileA(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
            if (fd.cFileName[0] == '.') continue;
            join_path(sub, sizeof(sub), root, fd.cFileName);
            join_path(cand, sizeof(cand), sub, "Target.dll");
            if (trial_check(t, cand)) {
                lstrcpynA(out, cand, (int)cap);
                CloseHandle(h);
                return 1;
            }
        } while (FindNextFileA(h, &fd));
        CloseHandle(h);
    }
    return 0;
}

/*
 * Resolve the payload DLL.
 *   1. explicit --dll <path>                (hard failure if missing)
 *   2. positional file from --inject <file> <pid>
 *   3. working directory
 *   4. client directory
 *   5. <repo>\Assets\DLL
 *   6. <repo>\**\Target.dll
 */
static int resolve_target_dll_ex(const char *explicitDll, const char *positionalDll,
                                  char *out, size_t cap, PATH_TRIALS *t,
                                  char *err, size_t errCap)
{
    char clientDir[MAX_PATH];
    char cwd[MAX_PATH];
    char cand[MAX_PATH];
    char modulePath[MAX_PATH];
    char *slash;

    if (explicitDll != NULL && explicitDll[0] != '\0') {
        if (trial_check(t, explicitDll)) {
            lstrcpynA(out, explicitDll, (int)cap);
            return 1;
        }
        snprintf(err, errCap,
                 "explicit --dll path does not exist: %s", explicitDll);
        return 0;
    }

    if (positionalDll != NULL && positionalDll[0] != '\0') {
        if (trial_check(t, positionalDll)) {
            lstrcpynA(out, positionalDll, (int)cap);
            return 1;
        }
    }

    /* client directory */
    clientDir[0] = '\0';
    if (GetModuleFileNameA(NULL, modulePath, (DWORD)sizeof(modulePath)) != 0) {
        lstrcpynA(clientDir, modulePath, MAX_PATH);
        slash = strrchr(clientDir, '\\');
        if (slash != NULL) *slash = '\0';
    }

    /* 3. working directory */
    if (GetCurrentDirectoryA((DWORD)sizeof(cwd), cwd) != 0) {
        join_path(cand, sizeof(cand), cwd, "Target.dll");
        if (trial_check(t, cand)) { lstrcpynA(out, cand, (int)cap); return 1; }
        join_path(cand, sizeof(cand), cwd, "SyntheticDll.dll");
        if (trial_check(t, cand)) { lstrcpynA(out, cand, (int)cap); return 1; }
        if (find_cwd_single_dll(t, cand, sizeof(cand))) {
            lstrcpynA(out, cand, (int)cap);
            return 1;
        }
    }

    /* 4. client directory */
    if (clientDir[0] != '\0') {
        join_path(cand, sizeof(cand), clientDir, "Target.dll");
        if (trial_check(t, cand)) { lstrcpynA(out, cand, (int)cap); return 1; }
        join_path(cand, sizeof(cand), clientDir, "SyntheticDll.dll");
        if (trial_check(t, cand)) { lstrcpynA(out, cand, (int)cap); return 1; }
        join_path(cand, sizeof(cand), clientDir, "..\\DLL\\Target.dll");
        if (trial_check(t, cand)) {
            char full[MAX_PATH];
            DWORD r = GetFullPathNameA(cand, (DWORD)sizeof(full), full, NULL);
            if (r != 0 && r < sizeof(full)) { lstrcpynA(out, full, (int)cap); return 1; }
            lstrcpynA(out, cand, (int)cap);
            return 1;
        }
        join_path(cand, sizeof(cand), clientDir, "..\\DLL\\SyntheticDll.dll");
        if (trial_check(t, cand)) {
            char full[MAX_PATH];
            DWORD r = GetFullPathNameA(cand, (DWORD)sizeof(full), full, NULL);
            if (r != 0 && r < sizeof(full)) { lstrcpynA(out, full, (int)cap); return 1; }
            lstrcpynA(out, cand, (int)cap);
            return 1;
        }
    }

    /* 5. <repo>\Assets\DLL */
    if (clientDir[0] != '\0') {
        if (find_assets_dll(clientDir, "Target.dll", cand, sizeof(cand), t)) {
            lstrcpynA(out, cand, (int)cap);
            return 1;
        }
        if (find_assets_dll(clientDir, "SyntheticDll.dll", cand, sizeof(cand), t)) {
            lstrcpynA(out, cand, (int)cap);
            return 1;
        }
    }

    /* 6. <repo>\Target.dll (single level recursive) */
    {
        char root[MAX_PATH];
        lstrcpynA(root, clientDir[0] ? clientDir : ".", MAX_PATH);
        slash = strrchr(root, '\\');
        if (slash != NULL && slash != root) *slash = '\0';
        if (find_target_under_root(root, cand, sizeof(cand), t)) {
            lstrcpynA(out, cand, (int)cap);
            return 1;
        }
    }

    snprintf(err, errCap, "no DLL found");
    return 0;
}

static void print_dll_failure(const PATH_TRIALS *t, const char *err)
{
    int i;
    char cwdList[1024];
    char clientList[1024];
    char cwd[MAX_PATH];
    char clientDir[MAX_PATH];
    char modulePath[MAX_PATH];
    char *slash;

    clientDir[0] = '\0';
    if (GetModuleFileNameA(NULL, modulePath, (DWORD)sizeof(modulePath)) != 0) {
        lstrcpynA(clientDir, modulePath, MAX_PATH);
        slash = strrchr(clientDir, '\\');
        if (slash != NULL) *slash = '\0';
    }

    printf("FAIL: %s\n", err);
    printf("  Tried:\n");
    for (i = 0; i < t->count; i++)
        printf("    %s\n", t->paths[i]);

    if (GetCurrentDirectoryA((DWORD)sizeof(cwd), cwd) != 0)
        list_dlls_in(cwd, cwdList, sizeof(cwdList));
    else
        lstrcpynA(cwdList, "(unknown)", (int)sizeof(cwdList));
    printf("  DLLs visible in CWD: %s\n", cwdList);

    if (clientDir[0] != '\0')
        list_dlls_in(clientDir, clientList, sizeof(clientList));
    else
        lstrcpynA(clientList, "(unknown)", (int)sizeof(clientList));
    printf("  DLLs visible in client dir: %s\n", clientList);

    if (t->ambiguous[0] != '\0')
        printf("  Ambiguous CWD candidates: %s\n", t->ambiguous);

    printf("  Pass --dll <path> to specify explicitly.\n");
}

/* ------------------------------------------------------------------ */
/* Channel attach / status                                             */
/* ------------------------------------------------------------------ */

static INJECTOR_CHANNEL *attach_channel(void)
{
    const int kMaxAttempts = 50;
    const DWORD kDelayMs = 100;
    int attempt;
    INJECTOR_CHANNEL *ch = NULL;

    for (attempt = 0; attempt < kMaxAttempts; attempt++) {
        __try {
            ch = (INJECTOR_CHANNEL *)INJECTOR_CHANNEL_USER_VA;
            if (ch->Magic == INJECTOR_CHANNEL_MAGIC &&
                ch->AbiVersion == 6) {
                printf("  Channel's Magic: ");
                green_value("0x%016llX", (unsigned long long)ch->Magic);
                printf("\n\n");
                return ch;
            }

            printf("  magic/ABI mismatch (magic expected=0x%016llX got=0x%016llX, abi=%u)\n",
                   (unsigned long long)INJECTOR_CHANNEL_MAGIC,
                   (unsigned long long)ch->Magic,
                   (unsigned)ch->AbiVersion);
            return NULL;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

        }
        Sleep(kDelayMs);
    }

    return NULL;
}

static int run_status(INJECTOR_CHANNEL *ch)
{
    if (ch == NULL) {
        printf("  status: channel not attached\n");
        return 1;
    }
    printf("  CHANNEL OK: ABI = ");
    green_value("%u", (unsigned)ch->AbiVersion);
    printf(" PID = ");
    green_value("%u", ch->Pid);
    printf(" Head = ");
    green_value("%ld", ch->Head);
    printf(" Tail = ");
    green_value("%ld", ch->Tail);
    printf(" Done = ");
    green_value("%ld\n", ch->Done);
    printf("  Channel Size: ");
    green_value("%u", (unsigned)sizeof(INJECTOR_CHANNEL));
    printf("\n\n");
    printf("  ObCallback Initialization: ");
    green_value("0x%08lX", (unsigned long)ch->ObInitStatus);
    printf(" | Gadget: ");
    green_value("0x%016llX\n", (unsigned long long)ch->GadgetVa);
    printf("  ObCallback Status: ");
    green_value("0x%08lX\n", (unsigned long)ch->ObCallbackStatus);
    printf("\n");
    printf("  TLS Slot: ");
    green_value("%ld", ch->TlsSlot);
    printf(" | TLS Status: ");
    green_value("0x%08lX", (unsigned long)ch->TlsStatus);
    printf(" | TLS Threads Seeded: ");
    green_value("%ld\n", ch->TlsThreadsSeeded);
    return 0;
}

static DWORD find_process_by_name(const char *name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    WCHAR want[MAX_PATH];
    WCHAR wantAlt[MAX_PATH];
    char alt[MAX_PATH];

    str_to_wide(name, want, MAX_PATH);
    if (strchr(name, '.') == NULL) {
        snprintf(alt, sizeof(alt), "%s.exe", name);
        str_to_wide(alt, wantAlt, MAX_PATH);
    } else {
        wantAlt[0] = L'\0';
    }

    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (wide_icmp(pe.szExeFile, want) == 0 ||
                (wantAlt[0] != L'\0' && wide_icmp(pe.szExeFile, wantAlt) == 0)) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Payload transfer                                                    */
/* ------------------------------------------------------------------ */

static int send_payload(INJECTOR_CHANNEL *ch, const unsigned char *buf, size_t len)
{
    size_t offset = 0;
    DWORD lastProgress = GetTickCount();
    while (offset < len) {
        long head = InterlockedCompareExchange(&ch->Head, 0, 0);
        long tail = InterlockedCompareExchange(&ch->Tail, 0, 0);
        unsigned int inUse = (unsigned int)(head - tail);
        if (inUse >= INJECTOR_CHANNEL_RING_SIZE) {
            Sleep(1);
            if (GetTickCount() - lastProgress > 5000) {
                printf("  transfer stalled at %zu/%zu\n", offset, len);
                return 0;
            }
            continue;
        }
        unsigned int space = INJECTOR_CHANNEL_RING_SIZE - inUse;
        unsigned int want = (unsigned int)(len - offset);
        if (want > space) want = space;
        unsigned int ringIdx = (unsigned int)head % INJECTOR_CHANNEL_RING_SIZE;
        unsigned int first = INJECTOR_CHANNEL_RING_SIZE - ringIdx;
        if (first > want) first = want;
        memcpy(ch->Ring + ringIdx, buf + offset, first);
        if (want > first) memcpy(ch->Ring, buf + offset + first, want - first);
        InterlockedExchange(&ch->Head, head + (long)want);
        offset += want;
        lastProgress = GetTickCount();
    }
    return 1;
}

static int wait_done(INJECTOR_CHANNEL *ch, DWORD timeoutMs)
{
    DWORD start = GetTickCount();
    while (InterlockedCompareExchange(&ch->Done, 0, 0) == 0) {
        if (GetTickCount() - start > timeoutMs) return 0;
        Sleep(1);
    }
    return 1;
}

static const char *ntstatus_hint(long st)
{
    switch ((unsigned long)st) {
    case 0x00000000UL: return "STATUS_SUCCESS";
    case 0xC0000001UL: return "STATUS_UNSUCCESSFUL (generic; check driver DbgPrint)";
    case 0xC0000008UL: return "STATUS_INVALID_HANDLE (target PID not found)";
    case 0xC000000DUL: return "STATUS_INVALID_PARAMETER (bad RVA or PID)";
    case 0xC000000FUL: return "STATUS_NO_SUCH_FILE (payload not found)";
    case 0xC0000018UL: return "STATUS_CONFLICTING_ADDRESSES (target VA taken)";
    case 0xC0000022UL: return "STATUS_ACCESS_DENIED (handle protection blocked)";
    case 0xC0000034UL: return "STATUS_OBJECT_NAME_NOT_FOUND";
    case 0xC0000035UL: return "STATUS_OBJECT_NAME_COLLISION (altitude conflict)";
    case 0xC000007BUL: return "STATUS_INVALID_IMAGE_FORMAT (PE rejected by parser)";
    case 0xC0000135UL: return "STATUS_DLL_NOT_FOUND (payload import missing)";
    case 0xC0000142UL: return "STATUS_DLL_INIT_FAILED (payload DllMain/ManualEntry faulted)";
    case 0xC00000A3UL: return "STATUS_NOT_READY (ObCallback protection not engaged; inject applies it automatically)";
    case 0xC0000225UL: return "STATUS_NOT_FOUND (module or export missing)";
    case 0xC0000409UL: return "STATUS_STACK_BUFFER_OVERRUN (payload /GS tripped)";
    default:           return "(unmapped; see driver DbgPrint with INJECTOR_DIAG=1)";
    }
}

/* ------------------------------------------------------------------ */
/* Injection plan                                                      */
/* ------------------------------------------------------------------ */

typedef struct _INJECT_PLAN {
    char          DllPath[MAX_PATH];
    unsigned char *Buf;
    size_t        Len;
    INJECTOR_PE   Pe;
    BOOL          PeParsed;
    BOOL          NotFound;
    EXPORT_CHOICE Choice;
    unsigned int  EntryRva;
} INJECT_PLAN;

static void plan_free(INJECT_PLAN *plan)
{
    if (plan == NULL) return;
    pe_free(&plan->Pe);
    if (plan->Buf != NULL) free(plan->Buf);
    plan->Buf = NULL;
    plan->Len = 0;
}
static int plan_prepare(INJECT_PLAN *plan, const char *dllOverride,
                        const char *positionalDll, const char *exportOverride,
                        BOOL haveRva, DWORD rvaValue,
                        PATH_TRIALS *trials, char *err, size_t errCap)
{
    char perr[512];
    char derr[512];

    memset(plan, 0, sizeof(*plan));

    derr[0] = '\0';
    if (!resolve_target_dll_ex(dllOverride, positionalDll, plan->DllPath,
                               sizeof(plan->DllPath), trials, derr, sizeof(derr))) {
        snprintf(err, errCap, "%s", derr[0] ? derr : "no DLL found");
        plan->NotFound = TRUE;
        return 0;
    }
    printf("  payload: %s\n", plan->DllPath);

    if (!file_read_all(plan->DllPath, &plan->Buf, &plan->Len, perr, sizeof(perr))) {
        snprintf(err, errCap, "%s", perr);
        return 0;
    }
    if (plan->Len == 0 || plan->Len > INJECTOR_PAYLOAD_MAX) {
        snprintf(err, errCap,
                 "payload size %zu out of range (max %u)",
                 plan->Len, INJECTOR_PAYLOAD_MAX);
        return 0;
    }

    /* Parse the very same buffer that will be handed to the driver, so the
       validated image and the injected bytes can never disagree. */
    memset(&plan->Pe, 0, sizeof(plan->Pe));
    if (!pe_parse_buffer(plan->Buf, plan->Len, &plan->Pe, perr, sizeof(perr))) {
        snprintf(err, errCap, "%s", perr);
        return 0;
    }
    plan->PeParsed = TRUE;
    pe_parse_exports(&plan->Pe);

    printf("  PE: %s  magic=0x%03X  SizeOfImage=0x%X  sections=%u  file=%zu bytes\n",
           pe_arch_text(&plan->Pe),
           (unsigned)plan->Pe.Nt.OptionalHeader.Magic,
           (unsigned)plan->Pe.Nt.OptionalHeader.SizeOfImage,
           (unsigned)plan->Pe.NumberOfSections,
           plan->Len);
    if (plan->Pe.HasExportDir) {
        printf("  export directory: present (RVA=0x%X size=0x%X)  names=%u functions=%u\n",
               (unsigned)plan->Pe.ExportDirRva,
               (unsigned)plan->Pe.ExportDirSize,
               (unsigned)plan->Pe.NumberOfNames,
               (unsigned)plan->Pe.NumberOfFunctions);
    } else {
        printf("  export directory: absent\n");
    }

    perr[0] = '\0';
    if (!discover_export(&plan->Pe, exportOverride, haveRva, rvaValue,
                         &plan->Choice, perr, sizeof(perr))) {
        snprintf(err, errCap, "%s", perr[0] ? perr : "no acceptable export");
        return 0;
    }
    plan->EntryRva = plan->Choice.rva;

    return 1;
}

/* Follow a forwarded export one level.  Returns the payload-relative RVA if
   the forwarder points back into the payload itself, otherwise reports where
   it lands in the target and why it cannot be the entry point. */
static int resolve_forwarded_entry(const INJECTOR_PE *pe, const EXPORT_CHOICE *choice,
                                    DWORD pid, DWORD *outRva,
                                    char *err, size_t errCap)
{
    char fwd[256];
    char module[128];
    char symbol[128];
    const char *dot;
    size_t mlen;
    DWORD sysRva = 0;
    char ferr[512];

    if (!pe_forwarder_string(pe, choice->rva, fwd, sizeof(fwd))) {
        snprintf(err, errCap, "cannot read the forwarder string at RVA 0x%X",
                 (unsigned)choice->rva);
        return 0;
    }
    printf("  forwarded export: %s -> \"%s\"\n", choice->name, fwd);

    dot = strchr(fwd, '.');
    if (dot == NULL) {
        snprintf(err, errCap,
                 "malformed forwarder string \"%s\" (expected MODULE.SYMBOL)", fwd);
        return 0;
    }
    mlen = (size_t)(dot - fwd);
    if (mlen >= sizeof(module)) mlen = sizeof(module) - 1;
    memcpy(module, fwd, mlen);
    module[mlen] = '\0';
    lstrcpynA(symbol, dot + 1, (int)sizeof(symbol));

    /* A forwarder back into the payload itself is payload-relative and works. */
    if (pe->DllName[0] != '\0' && module_basename_match(pe->DllName, module)) {
        DWORD rva = 0;
        if (pe_find_export(pe, symbol, 1, &rva, NULL) ||
            pe_find_export(pe, symbol, 0, &rva, NULL)) {
            if (pe_is_forwarded(pe, rva)) {
                snprintf(err, errCap,
                         "forwarded export \"%s\" loops back into the export "
                         "directory; refusing to follow it", fwd);
                return 0;
            }
            printf("  forwarder resolves inside the payload: RVA 0x%X\n",
                   (unsigned)rva);
            *outRva = rva;
            return 1;
        }
        snprintf(err, errCap,
                 "forwarded export \"%s\" names symbol '%s' which the payload "
                 "does not export", fwd, symbol);
        return 0;
    }

    ferr[0] = '\0';
    if (!resolve_system_export(module, symbol, &sysRva, ferr, sizeof(ferr))) {
        snprintf(err, errCap, "cannot resolve forwarder \"%s\": %s", fwd, ferr);
        return 0;
    }

    printf("  forwarder resolves to %s+0x%X", module, (unsigned)sysRva);
    {
        unsigned long long base = 0;
        if (find_target_module_base(pid, module, &base)) {
            printf(" (target VA 0x%016llX)", base + sysRva);
        }
    }
    printf("\n");

    snprintf(err, errCap,
             "forwarded export \"%s\" resolves to %s+0x%X, which is outside the "
             "payload image. The driver executes at payload_base + rva and "
             "rejects addresses outside the mapped payload, so a forwarded "
             "export cannot be the entry point. Use --rva <hex> to target a "
             "code offset inside the payload.", fwd, module, (unsigned)sysRva);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Injection                                                           */
/* ------------------------------------------------------------------ */

static int inject_map(INJECTOR_CHANNEL *ch, unsigned int pid, INJECT_PLAN *plan,
                       int verbose)
{
    unsigned char *buf = plan->Buf;
    size_t len = plan->Len;
    int settleMs = g_settleMs;

    if (ch->AbiVersion != 6) {
        printf("  driver ABI too old (need 6)\n");
        return 2;
    }

    if (DeleteFileA("C:\\Windows\\Temp\\injector_diag.log")) {
        printf("  cleanup: diag log deleted\n");
    } else if (GetLastError() == ERROR_FILE_NOT_FOUND) {
        printf("  cleanup: no diag log present\n");
    } else if (GetLastError() == ERROR_ACCESS_DENIED) {
        printf("  cleanup: diag log owned by SYSTEM; will be deleted on next driver load\n");
    } else {
        printf("  cleanup: diag log delete failed (err %lu)\n", (unsigned long)GetLastError());
    }

    ch->ProtectedPid = pid;
    ch->ObCallbackStatus = 0;
    ch->GadgetVa = 0;
    if (ch->AbiVersion >= 6) ch->ObInitStatus = 0;
    InterlockedExchange(&ch->Done, 0);
    InterlockedExchange(&ch->Cmd, INJECTOR_CMD_PROTECT_PID);
    if (!wait_done(ch, 5000)) {
        printf("  protect: CMD_PROTECT_PID timeout\n");
    } else {
        long pst = ch->ObCallbackStatus;
        unsigned long long gadget = ch->GadgetVa;
        InterlockedExchange(&ch->Done, 0);
        printf("  protect: status=0x%08lX pid=%u gadget=0x%016llX ob_init=0x%08lX\n",
               (unsigned long)pst, pid, gadget, (unsigned long)ch->ObInitStatus);
    }

    /* The driver resolves the payload's imports against the modules that are
       ALREADY loaded in the target.  Give the target time to finish loading
       its own DLLs before the map is attempted. */
    if (settleMs > 0) {
        DWORD start = GetTickCount();
        printf("  settle: waiting %d ms for the target to finish loading modules...",
               settleMs);
        fflush(stdout);
        while ((LONG)(GetTickCount() - start) < settleMs) {
            Sleep(50);
        }
        printf(" done (%lu ms elapsed)\n",
               (unsigned long)(GetTickCount() - start));
    }

    ch->Head = 0; ch->Tail = 0;
    ch->PayloadSize = (unsigned int)len;
    ch->PayloadReceived = 0;
    ch->Pid = pid;
    ch->Flags = 0;
    ch->CmdStatus = 0;
    ch->RemoteBase = 0;
    ch->RelocCount = 0;
    ch->ImportDllCount = 0;
    ch->TlsSlot = -1;
    ch->TlsStatus = 0;
    ch->TlsThreadsSeeded = 0;
    ch->ExecutionVa = 0;
    ch->HijackThreadId = 0;
    ch->HijackReserved = 0;
    InterlockedExchange(&ch->Done, 0);
    InterlockedExchange(&ch->Cmd, INJECTOR_CMD_NONE);

    if (!send_payload(ch, buf, len)) return 3;
    printf("  payload sent: %zu bytes; signalling CMD_MAP\n", len);

    InterlockedExchange(&ch->Cmd, INJECTOR_CMD_MAP);

    if (!wait_done(ch, 10000)) {
        printf("  timeout waiting for driver\n");
        return 4;
    }
    long st = ch->CmdStatus;
    unsigned long long base = ch->RemoteBase;
    InterlockedExchange(&ch->Done, 0);

    printf("  driver status = 0x%08lX\n", (unsigned long)st);
    if (st != 0) {
        printf("  inject failed: status=0x%08lX (%s)\n",
               (unsigned long)st, ntstatus_hint(st));
        printf("  tls: slot=%ld status=0x%08lX threads_seeded=%ld\n",
               (long)ch->TlsSlot, (unsigned long)ch->TlsStatus,
               (long)ch->TlsThreadsSeeded);
        return 5;
    }

    printf("  inject OK: base=0x%016llX\n", base);
    printf("  tls: slot=%ld status=0x%08lX threads_seeded=%ld\n",
           (long)ch->TlsSlot, (unsigned long)ch->TlsStatus,
           (long)ch->TlsThreadsSeeded);
    if (verbose) {
        printf("  relocations: %llu   import dlls: %llu\n",
               (unsigned long long)ch->RelocCount,
               (unsigned long long)ch->ImportDllCount);
    }
    return 0;
}

static int inject_exec(INJECTOR_CHANNEL *ch, INJECT_PLAN *plan)
{
    unsigned long long execVa = ch->RemoteBase + plan->EntryRva;

    printf("  sending CMD_EXEC execVa=0x%016llX\n", execVa);
    ch->ExecutionVa = execVa;
    ch->HijackThreadId = 0;
    ch->HijackReserved = 0;
    InterlockedExchange(&ch->Done, 0);
    InterlockedExchange(&ch->Cmd, INJECTOR_CMD_EXEC);
    if (!wait_done(ch, 5000)) {
        printf("  CMD_EXEC timeout\n");
        return 7;
    }
    long est = ch->CmdStatus;
    long tid = ch->HijackThreadId;
    InterlockedExchange(&ch->Done, 0);
    printf("  exec status=0x%08lX (%s) thread_id=%ld\n",
           (unsigned long)est, ntstatus_hint(est), tid);
    if (est != 0) return 8;
    return 0;
}

static int run_inject(INJECTOR_CHANNEL *ch, unsigned int pid,
                      const char *dllOverride, const char *positionalDll,
                      const char *exportOverride,
                      BOOL haveRva, DWORD rvaValue)
{
    INJECT_PLAN plan;
    PATH_TRIALS trials;
    char err[512];
    int rc;

    memset(&plan, 0, sizeof(plan));
    memset(&trials, 0, sizeof(trials));
    err[0] = '\0';

    if (!plan_prepare(&plan, dllOverride, positionalDll, exportOverride,
                      haveRva, rvaValue, &trials, err, sizeof(err))) {
        if (plan.NotFound) {
            print_dll_failure(&trials, err[0] ? err : "no DLL found");
        } else {
            printf("  FAIL: %s\n", err);
            if (plan.PeParsed) pe_dump_exports(&plan.Pe, plan.DllPath);
        }
        plan_free(&plan);
        return 2;
    }

    if (plan.Choice.forwarded) {
        DWORD fwdRva = 0;
        char ferr[768];
        ferr[0] = '\0';
        if (!resolve_forwarded_entry(&plan.Pe, &plan.Choice, pid, &fwdRva,
                                     ferr, sizeof(ferr))) {
            printf("  FAIL: %s\n", ferr);
            plan_free(&plan);
            return 2;
        }
        plan.EntryRva = fwdRva;
    }

    /* Keep the historical "RVA resolved from" line so existing operator
       scripts that match on it keep working. */
    if (plan.Choice.origin[0] != '\0' &&
        _strnicmp(plan.Choice.origin, "explicit --rva", 13) != 0) {
        printf("  %s RVA resolved from %s -> 0x%X\n",
               plan.Choice.name, plan.DllPath, plan.EntryRva);
    }
    printf("  entry point: %s  RVA=0x%X  (%s)\n",
           plan.Choice.name, plan.EntryRva, plan.Choice.origin);

    rc = inject_map(ch, pid, &plan, 1);
    if (rc == 0)
        rc = inject_exec(ch, &plan);
    plan_free(&plan);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Self-test modes                                                     */
/* ------------------------------------------------------------------ */

/*
 * End-to-end self test.  Five independent checks, each backed by real
 * driver state; nothing here is hard-coded.
 */
static int run_selftest(INJECTOR_CHANNEL *ch, unsigned int pid,
                         const char *dllOverride, const char *exportOverride)
{
    INJECT_PLAN plan;
    PATH_TRIALS trials;
    char err[512];
    int passed = 0;
    int total = 5;
    int rc;
    unsigned long long ackBefore = 0;
    unsigned long long ackAfter = 0;
    BOOL ackChanged = FALSE;

    memset(&plan, 0, sizeof(plan));
    memset(&trials, 0, sizeof(trials));
    err[0] = '\0';

    printf("\n=== SELFTEST (client-side adaptive injection gate) ===\n");

    printf("[1/5] channel attach .............. ");
    if (ch != NULL && ch->Magic == INJECTOR_CHANNEL_MAGIC && ch->AbiVersion == 6) {
        printf("PASS (magic=0x%016llX ABI=%u)\n",
               (unsigned long long)ch->Magic, (unsigned)ch->AbiVersion);
        passed++;
    } else {
        printf("FAIL (channel not attached or bad ABI)\n");
    }

    printf("[2/5] payload + export resolution\n");
    if (plan_prepare(&plan, dllOverride, NULL, exportOverride, FALSE, 0,
                     &trials, err, sizeof(err))) {
        printf("  -> PASS (%s -> %s RVA=0x%X)\n", plan.DllPath,
               plan.Choice.name, plan.EntryRva);
        passed++;
    } else {
        printf("  -> FAIL (%s)\n", err);
        if (plan.PeParsed) pe_dump_exports(&plan.Pe, plan.DllPath);
        printf("\n=== SELFTEST FAIL (%d/%d) ===\n", passed, total);
        plan_free(&plan);
        return 2;
    }

    ackBefore = ch->SelfTestAck;

    printf("[3/5] driver map\n");
    rc = inject_map(ch, pid, &plan, 0);
    if (rc == 0) {
        printf("  -> PASS (base=0x%016llX)\n", (unsigned long long)ch->RemoteBase);
        passed++;
    } else {
        printf("  -> FAIL (rc=%d)\n", rc);
        printf("\n=== SELFTEST FAIL (%d/%d) ===\n", passed, total);
        plan_free(&plan);
        return 2;
    }

    printf("[4/5] driver exec\n");
    rc = inject_exec(ch, &plan);
    if (rc == 0) {
        printf("  -> PASS (thread_id=%ld)\n", (long)ch->HijackThreadId);
        passed++;
    } else {
        printf("  -> FAIL (rc=%d)\n", rc);
        printf("\n=== SELFTEST FAIL (%d/%d) ===\n", passed, total);
        plan_free(&plan);
        return 2;
    }

    /* CMD_EXEC only completes the thread hijack; the payload body may still
       be running.  Give it a bounded window to reach the channel. */
    {
        DWORD start = GetTickCount();
        while (GetTickCount() - start < 2000) {
            ackAfter = ch->SelfTestAck;
            if (ackAfter != ackBefore) { ackChanged = TRUE; break; }
            Sleep(10);
        }
        ackAfter = ch->SelfTestAck;
    }

    printf("[5/5] tls / driver state\n");
    if (ch->TlsStatus == 0) {
        printf("  -> PASS (tls_slot=%ld tls_status=0x%08lX threads_seeded=%ld)\n",
               (long)ch->TlsSlot, (unsigned long)ch->TlsStatus,
               (long)ch->TlsThreadsSeeded);
        passed++;
    } else {
        printf("  -> FAIL (tls_status=0x%08lX)\n", (unsigned long)ch->TlsStatus);
    }
    printf("  channel selftest_ack: 0x%016llX (before=0x%016llX%s)\n",
           (unsigned long long)ackAfter, (unsigned long long)ackBefore,
           ackChanged ? ", payload wrote the channel" : ", unchanged");

    plan_free(&plan);

    if (passed == total) {
        printf("\n=== SELFTEST PASS (%d/%d) ===\n", passed, total);
        return 0;
    }
    printf("\n=== SELFTEST FAIL (%d/%d) ===\n", passed, total);
    return 2;
}

/*
 * Cross-check the client's own PE parser against the Windows loader and
 * against the driver's channel contract.  No injection is performed.
 */
static int run_crosscheck_selftest(INJECTOR_CHANNEL *ch, const char *dllOverride,
                                   const char *positionalDll)
{
    INJECT_PLAN plan;
    PATH_TRIALS trials;
    char err[512];
    int passed = 0;
    int total = 5;
    DWORD i;
    HMODULE hMod = NULL;
    DWORD nameMismatch = 0;
    DWORD rvaMismatch = 0;
    DWORD nameChecked = 0;
    DWORD rvaChecked = 0;

    memset(&plan, 0, sizeof(plan));
    memset(&trials, 0, sizeof(trials));
    err[0] = '\0';

    printf("\n=== CROSSCHECK-SELFTEST ===\n");

    printf("[1/5] PE header validation\n");
    if (plan_prepare(&plan, dllOverride, positionalDll, NULL, FALSE, 0,
                     &trials, err, sizeof(err))) {
        printf("  -> PASS (%s)\n", pe_arch_text(&plan.Pe));
        passed++;
    } else {
        printf("  -> FAIL (%s)\n", err);
        printf("\nCrosscheck %d/%d FAIL\n", passed, total);
        plan_free(&plan);
        return 2;
    }

    printf("[2/5] export directory state\n");
    {
        BOOL headerSaysAbsent =
            (plan.Pe.Nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) ||
            (plan.Pe.Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0);
        BOOL parserSaysAbsent = !plan.Pe.HasExportDir;
        if (headerSaysAbsent == parserSaysAbsent) {
            printf("  -> PASS (%s, names=%u functions=%u)\n",
                   parserSaysAbsent ? "absent" : "present",
                   (unsigned)plan.Pe.NumberOfNames,
                   (unsigned)plan.Pe.NumberOfFunctions);
            passed++;
        } else {
            printf("  -> FAIL (header and parser disagree)\n");
        }
    }

    hMod = LoadLibraryExA(plan.DllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hMod == NULL) {
        printf("[3/5] loader name agreement ....... FAIL (LoadLibraryEx error %lu)\n",
               (unsigned long)GetLastError());
        printf("[4/5] loader RVA agreement ....... FAIL (skipped)\n");
    } else {
        printf("[3/5] loader name agreement ....... ");
        for (i = 0; i < plan.Pe.NumberOfNames; i++) {
            char tmp[INJECTOR_MAX_NAME_LEN];
            const char *n = pe_export_name(&plan.Pe, i, tmp, sizeof(tmp));
            FARPROC p;

            if (n == NULL) continue;
            p = GetProcAddress(hMod, n);
            nameChecked++;
            if (p == NULL) {
                nameMismatch++;
                printf("\n    loader cannot resolve '%s'\n", n);
            }
        }
        if (nameMismatch == 0) {
            printf("PASS (%u named exports)\n", (unsigned)nameChecked);
            passed++;
        } else {
            printf("FAIL (%u of %u)\n", (unsigned)nameMismatch, (unsigned)nameChecked);
        }

        printf("[4/5] loader RVA agreement ........ ");
        for (i = 0; i < plan.Pe.NumberOfNames; i++) {
            char tmp[INJECTOR_MAX_NAME_LEN];
            const char *n = pe_export_name(&plan.Pe, i, tmp, sizeof(tmp));
            FARPROC p;
            DWORD clientRva;
            DWORD loaderRva;

            if (n == NULL) continue;
            if (plan.Pe.NameOrdinals[i] >= plan.Pe.NumberOfFunctions) continue;
            clientRva = plan.Pe.FuncRvas[plan.Pe.NameOrdinals[i]];
            if (pe_is_forwarded(&plan.Pe, clientRva)) continue; /* forwarders resolve elsewhere */
            p = GetProcAddress(hMod, n);
            if (p == NULL) continue;
            loaderRva = (DWORD)((const unsigned char *)p -
                                (const unsigned char *)hMod);
            rvaChecked++;
            if (loaderRva != clientRva) {
                rvaMismatch++;
                printf("\n    %s: client=0x%X loader=0x%X\n", n,
                       (unsigned)clientRva, (unsigned)loaderRva);
            }
        }
        if (rvaMismatch == 0) {
            printf("PASS (%u exports, %u forwarders skipped)\n",
                   (unsigned)rvaChecked,
                   (unsigned)(plan.Pe.NumberOfNames - rvaChecked));
            passed++;
        } else {
            printf("FAIL (%u of %u)\n", (unsigned)rvaMismatch, (unsigned)rvaChecked);
        }
    }

    printf("[5/5] client/driver channel contract ");
    if (sizeof(INJECTOR_CHANNEL) == 0x4090 &&
        offsetof(INJECTOR_CHANNEL, SelfTestAck) == INJECTOR_SELFTEST_ACK_OFFSET &&
        offsetof(INJECTOR_CHANNEL, Ring) == 0x90 &&
        INJECTOR_CHANNEL_USER_VA == 0x00007FF000000000ULL &&
        (ch == NULL || (ch->Magic == INJECTOR_CHANNEL_MAGIC && ch->AbiVersion == 6))) {
        printf("PASS (size=0x%X ack=0x%llX ring=0x%X abi=6)\n",
               (unsigned)sizeof(INJECTOR_CHANNEL),
               (unsigned long long)INJECTOR_SELFTEST_ACK_OFFSET,
               (unsigned)offsetof(INJECTOR_CHANNEL, Ring));
        passed++;
    } else {
        printf("FAIL (client layout or live channel mismatch)\n");
    }

    if (hMod != NULL) FreeLibrary(hMod);
    plan_free(&plan);

    if (passed == total) {
        printf("\nCrosscheck %d/%d PASS\n", passed, total);
        return 0;
    }
    printf("\nCrosscheck %d/%d FAIL\n", passed, total);
    return 2;
}

/* ------------------------------------------------------------------ */
/* --list-exports                                                      */
/* ------------------------------------------------------------------ */

static int run_list_exports(const char *dllOverride, const char *positionalDll)
{
    INJECT_PLAN plan;
    PATH_TRIALS trials;
    char err[512];
    DWORD i;
    DWORD printed = 0;
    DWORD ordinalOnly = 0;

    memset(&plan, 0, sizeof(plan));
    memset(&trials, 0, sizeof(trials));
    err[0] = '\0';

    if (!plan_prepare(&plan, dllOverride, positionalDll, NULL, FALSE, 0,
                      &trials, err, sizeof(err))) {
        if (plan.NotFound) {
            print_dll_failure(&trials, err[0] ? err : "no DLL found");
        } else {
            printf("FAIL: %s\n", err);
            if (plan.PeParsed) pe_dump_exports(&plan.Pe, plan.DllPath);
        }
        plan_free(&plan);
        return 2;
    }

    printf("\nExport table of %s\n", plan.DllPath);
    printf("  Arch: %s\n", pe_arch_text(&plan.Pe));
    printf("  Optional header magic: 0x%03X   SizeOfImage: 0x%X   "
           "ImageBase: 0x%016llX\n",
           (unsigned)plan.Pe.Nt.OptionalHeader.Magic,
           (unsigned)plan.Pe.Nt.OptionalHeader.SizeOfImage,
           (unsigned long long)plan.Pe.Nt.OptionalHeader.ImageBase);
    printf("  AddressOfEntryPoint: 0x%X\n",
           (unsigned)plan.Pe.Nt.OptionalHeader.AddressOfEntryPoint);

    if (!plan.Pe.HasExportDir) {
        printf("  Export directory: absent (this image exports nothing)\n");
        plan_free(&plan);
        return 0;
    }

    printf("  Export directory: present (RVA=0x%X size=0x%X)  "
           "ordinal base=%u  functions=%u  names=%u\n",
           (unsigned)plan.Pe.ExportDirRva,
           (unsigned)plan.Pe.ExportDirSize,
           (unsigned)plan.Pe.ExportBase,
           (unsigned)plan.Pe.NumberOfFunctions,
           (unsigned)plan.Pe.NumberOfNames);
    if (plan.Pe.DllName[0] != '\0')
        printf("  DLL name: %s\n", plan.Pe.DllName);

    printf("  Named exports (%u):\n", (unsigned)plan.Pe.NumberOfNames);
    for (i = 0; i < plan.Pe.NumberOfNames; i++) {
        char tmp[INJECTOR_MAX_NAME_LEN];
        const char *n = pe_export_name(&plan.Pe, i, tmp, sizeof(tmp));
        DWORD rva = 0;
        const char *mark = "";

        if (n == NULL) continue;
        if (plan.Pe.NameOrdinals[i] < plan.Pe.NumberOfFunctions)
            rva = plan.Pe.FuncRvas[plan.Pe.NameOrdinals[i]];
        if (pe_is_forwarded(&plan.Pe, rva)) mark = "  (forwarded)";
        printf("    %-40s RVA=0x%08X  ord=%u%s\n", n, (unsigned)rva,
               (unsigned)(plan.Pe.ExportBase + plan.Pe.NameOrdinals[i]), mark);
        printed++;
    }
    if (printed == 0)
        printf("    (none)\n");

    printf("  Ordinal-only exports:\n");
    for (i = 0; i < plan.Pe.NumberOfFunctions; i++) {
        BOOL isNamed = FALSE;
        DWORD j;

        if (plan.Pe.FuncRvas[i] == 0) continue;
        for (j = 0; j < plan.Pe.NumberOfNames; j++) {
            if (plan.Pe.NameOrdinals[j] == (WORD)i) { isNamed = TRUE; break; }
        }
        if (isNamed) continue;
        printf("    %-40s RVA=0x%08X  ord=%u\n", "<unnamed>",
               (unsigned)plan.Pe.FuncRvas[i],
               (unsigned)(plan.Pe.ExportBase + i));
        ordinalOnly++;
    }
    if (ordinalOnly == 0)
        printf("    (none)\n");

    plan_free(&plan);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Interactive target discovery                                        */
/* ------------------------------------------------------------------ */

static int discover_target(INJECTOR_CHANNEL *ch)
{
    char name[MAX_PATH];
    DWORD pid;

    printf("\n----------------------------------------------------------------------------\n\n");
    printf("Process Name: ");
    fflush(stdout);
    if (fgets(name, sizeof(name), stdin) == NULL)
        name[0] = '\0';
    trim_input(name);

    if (name[0] == '\0') {
        printf("Process not found.\n\n");
        return 0;
    }

    pid = find_process_by_name(name);
    if (pid == 0) {
        printf("Process not found.\n\n");
        return 0;
    }
    printf("Process found. PID: ");
    green_value("%lu", (unsigned long)pid);
    printf("\n\n");

    printf("Press ");
    blue_value("[Enter]");
    printf(" to inject to the process.\n");
    if (!stdin_is_console())
        return 0;
    (void)getchar();
    return run_inject(ch, (unsigned int)pid, NULL, NULL, NULL, FALSE, 0);
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

typedef enum _CLI_MODE {
    CLI_MODE_INTERACTIVE = 0,
    CLI_MODE_STATUS,
    CLI_MODE_INJECT,
    CLI_MODE_LIST_EXPORTS,
    CLI_MODE_SELFTEST,
    CLI_MODE_CROSSCHECK
} CLI_MODE;

static void print_usage(const char *exe)
{
    printf("  usage:\n");
    printf("    %s                                    interactive mode\n", exe);
    printf("    %s --status                          driver health\n", exe);
    printf("    %s --inject <pid>                    inject the resolved payload\n", exe);
    printf("    %s --inject <file> <pid> [<rva>]     inject a specific payload\n", exe);
    printf("    %s --list-exports [--dll <path>]     print a DLL's export table\n", exe);
    printf("    %s --selftest <pid>                  end-to-end injection self-test\n", exe);
    printf("    %s --crosscheck-selftest             cross-check the PE parser\n", exe);
    printf("\n  options:\n");
    printf("    --dll <path>      explicit payload path (no fallback if missing)\n");
    printf("    --export <name>   explicit export name (skips auto-discovery)\n");
    printf("    --rva <hex>       explicit RVA, e.g. 0x1D10 or 1D10 (skips export lookup)\n");
    printf("    --settle <sec>    wait before mapping so the target finishes loading"
           " modules (default %d, 0 disables)\n",
           INJECTOR_DEFAULT_SETTLE_MS / 1000);
}

int main(int argc, char **argv)
{
    int rc = 1;
    int interactive = 1;
    CLI_MODE mode = CLI_MODE_INTERACTIVE;
    const char *dllPath = NULL;
    const char *exportName = NULL;
    const char *rvaStr = NULL;
    const char *pos[8];
    int nPos = 0;
    int i;
    INJECTOR_CHANNEL *ch;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (_stricmp(a, "--dll") == 0) {
            if (i + 1 >= argc) { printf("  --dll needs a path\n"); return 1; }
            dllPath = argv[++i];
        } else if (_stricmp(a, "--export") == 0) {
            if (i + 1 >= argc) { printf("  --export needs a name\n"); return 1; }
            exportName = argv[++i];
        } else if (_stricmp(a, "--rva") == 0) {
            if (i + 1 >= argc) { printf("  --rva needs a value\n"); return 1; }
            rvaStr = argv[++i];
        } else if (_stricmp(a, "--settle") == 0) {
            const char *v = NULL;
            double secs = 0.0;
            char *endp = NULL;
            if (i + 1 >= argc) { printf("  --settle needs a value in seconds\n"); return 1; }
            v = argv[++i];
            secs = strtod(v, &endp);
            if (endp == v || secs < 0.0 || secs > 3600.0) {
                printf("  invalid --settle value: %s (expected seconds, 0..3600)\n", v);
                return 1;
            }
            g_settleMs = (int)(secs * 1000.0);
        } else if (_stricmp(a, "--list-exports") == 0) {
            mode = CLI_MODE_LIST_EXPORTS;
        } else if (_stricmp(a, "--inject") == 0) {
            mode = CLI_MODE_INJECT;
        } else if (_stricmp(a, "--status") == 0) {
            mode = CLI_MODE_STATUS;
        } else if (_stricmp(a, "--selftest") == 0) {
            mode = CLI_MODE_SELFTEST;
        } else if (_stricmp(a, "--crosscheck-selftest") == 0) {
            mode = CLI_MODE_CROSSCHECK;
        } else if (a[0] == '-' && a[1] != '\0') {
            printf("  unknown option: %s\n", a);
            print_usage(argv[0]);
            return 1;
        } else {
            if (nPos < (int)(sizeof(pos) / sizeof(pos[0]))) pos[nPos++] = a;
        }
    }

    if (argc <= 1) {
        mode = CLI_MODE_INTERACTIVE;
        interactive = 1;
    } else {
        interactive = 0;
    }

    /* --list-exports does not need the driver. */
    if (mode == CLI_MODE_LIST_EXPORTS) {
        const char *positionalDll = (nPos >= 1) ? pos[0] : NULL;
        return run_list_exports(dllPath, positionalDll);
    }

    printf("Driver's Health:\n\n");
    print_channel_va();

    ch = attach_channel();

    if (ch != NULL && ch->AbiVersion != 6) {
        fprintf(stderr, "FATAL: channel ABI mismatch: driver reports %u, "
                        "client expects 6\n", ch->AbiVersion);
        return 1;
    }

    if (ch == NULL) {
        printf("  Driver is not mapped yet.\n");
        return 1;
    }

    switch (mode) {
    case CLI_MODE_INTERACTIVE:
        rc = run_status(ch);
        rc = discover_target(ch);
        break;

    case CLI_MODE_STATUS:
        rc = run_status(ch);
        break;

    case CLI_MODE_INJECT: {
        const char *positionalDll = NULL;
        const char *pidStr = NULL;
        const char *positionalRva = NULL;
        DWORD rvaValue = 0;
        BOOL haveRva = FALSE;

        if (nPos == 1) {
            pidStr = pos[0];
        } else if (nPos == 2) {
            positionalDll = pos[0];
            pidStr = pos[1];
        } else if (nPos >= 3) {
            positionalDll = pos[0];
            pidStr = pos[1];
            positionalRva = pos[2];
        } else {
            printf("  usage: %s --inject [<file>] <pid> [<rva>]\n", argv[0]);
            print_usage(argv[0]);
            return 1;
        }

        if (positionalRva != NULL) {
            if (!parse_hex_u32(positionalRva, &rvaValue)) {
                printf("  invalid RVA: %s (expected hexadecimal, e.g. 0x1D10)\n",
                       positionalRva);
                return 1;
            }
            haveRva = TRUE;
        }
        if (rvaStr != NULL) {
            if (!parse_hex_u32(rvaStr, &rvaValue)) {
                printf("  invalid --rva value: %s (expected hexadecimal, e.g. 0x1D10)\n",
                       rvaStr);
                return 1;
            }
            haveRva = TRUE;
        }

        rc = run_inject(ch, (unsigned int)strtoul(pidStr, NULL, 0),
                        dllPath, positionalDll, exportName, haveRva, rvaValue);
        break;
    }

    case CLI_MODE_SELFTEST: {
        const char *pidStr = (nPos >= 1) ? pos[0] : NULL;
        if (pidStr == NULL) {
            printf("  usage: %s --selftest <pid>\n", argv[0]);
            return 1;
        }
        rc = run_selftest(ch, (unsigned int)strtoul(pidStr, NULL, 0),
                          dllPath, exportName);
        break;
    }

    case CLI_MODE_CROSSCHECK:
        rc = run_crosscheck_selftest(ch, dllPath, (nPos >= 1) ? pos[0] : NULL);
        break;

    default:
        print_usage(argv[0]);
        rc = 1;
        break;
    }

    if (interactive)
        wait_for_enter();
    return rc;
}
