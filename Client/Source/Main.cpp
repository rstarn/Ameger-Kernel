
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

static int run_inject(INJECTOR_CHANNEL *ch, unsigned int pid);

static int stdin_is_console(void)
{
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;

    if (hIn == NULL || hIn == INVALID_HANDLE_VALUE) return 0;
    return GetConsoleMode(hIn, &mode) ? 1 : 0;
}

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
        if (ca == L'\0') return 0;
        a++;
        b++;
    }
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
    return run_inject(ch, (unsigned int)pid);
}

static void resolve_target_dll(char *out, size_t cap)
{
    char modulePath[MAX_PATH];
    char fn[MAX_PATH];

    if (GetModuleFileNameA(NULL, modulePath, (DWORD)sizeof(modulePath)) != 0) {
        char *slash = strrchr(modulePath, '\\');
        if (slash != NULL) {
            *slash = '\0';
            size_t n = (size_t)lstrlenA(modulePath);
            if (n + 14 < cap) {
                memcpy(fn, modulePath, n + 1);
                memcpy(fn + n, "\\Target.dll", 12);
                if (GetFileAttributesA(fn) != INVALID_FILE_ATTRIBUTES) {
                    lstrcpynA(out, fn, (int)cap);
                    return;
                }
            }
            if (n + 18 < cap) {
                memcpy(fn, modulePath, n + 1);
                memcpy(fn + n, "\\..\\DLL\\Target.dll", 19);
                if (GetFileAttributesA(fn) != INVALID_FILE_ATTRIBUTES) {
                    char root[MAX_PATH];
                    DWORD r = GetFullPathNameA(fn, (DWORD)sizeof(root), root, NULL);
                    if (r != 0 && r < sizeof(root)) {
                        lstrcpynA(out, root, (int)cap);
                        return;
                    }
                    lstrcpynA(out, fn, (int)cap);
                    return;
                }
            }
        }
    }
    lstrcpynA(out, "Target.dll", (int)cap);
}

static int read_file_all(const char *path, unsigned char **out, size_t *out_len)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("  cannot open %s: error %lu\n", path, (unsigned long)GetLastError());
        return 0;
    }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 0x40000000LL) {
        CloseHandle(h);
        printf("  file size invalid or > 1 GB\n");
        return 0;
    }
    unsigned char *buf = (unsigned char *)malloc((size_t)sz.QuadPart);
    if (!buf) { CloseHandle(h); printf("  out of memory\n"); return 0; }
    DWORD got = 0;
    if (!ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart) {
        free(buf); CloseHandle(h);
        printf("  read failed\n");
        return 0;
    }
    CloseHandle(h);
    *out = buf; *out_len = (size_t)sz.QuadPart;
    return 1;
}

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

static unsigned int rva_to_raw(const unsigned char *buf, size_t len, DWORD rva)
{
    __try {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        DWORD lfanew = (DWORD)dos->e_lfanew;
        if (lfanew + sizeof(IMAGE_NT_HEADERS64) > len) return 0;
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(buf + lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        WORD nsec = nt->FileHeader.NumberOfSections;
        DWORD secOff = lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                       nt->FileHeader.SizeOfOptionalHeader;
        if (secOff + (DWORD)nsec * sizeof(IMAGE_SECTION_HEADER) > len) return 0;
        IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)(buf + secOff);
        for (WORD i = 0; i < nsec; i++) {
            DWORD va = sec[i].VirtualAddress;
            DWORD vs = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            DWORD raw = sec[i].PointerToRawData;
            if (rva >= va && rva < va + vs) {
                DWORD off = raw + (rva - va);
                if (off < len) return off;
                return 0;
            }
        }
        if (rva < len) return rva;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return 0;
}

static unsigned int find_export_rva(const char *path, const char *name)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 0x40000000LL) {
        CloseHandle(h); return 0;
    }
    size_t len = (size_t)sz.QuadPart;
    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) { CloseHandle(h); return 0; }
    DWORD got = 0;
    if (!ReadFile(h, buf, (DWORD)len, &got, NULL) || got != (DWORD)len) {
        free(buf); CloseHandle(h); return 0;
    }
    CloseHandle(h);

    unsigned int rva = 0;
    __try {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto done;
        if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > len) goto done;
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(buf + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) goto done;
        DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (expRva == 0) goto done;
        DWORD expRaw = rva_to_raw(buf, len, expRva);
        if (expRaw == 0 || expRaw + sizeof(IMAGE_EXPORT_DIRECTORY) > len) goto done;
        IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(buf + expRaw);
        DWORD namesRaw = rva_to_raw(buf, len, exp->AddressOfNames);
        DWORD ordsRaw  = rva_to_raw(buf, len, exp->AddressOfNameOrdinals);
        DWORD funcsRaw = rva_to_raw(buf, len, exp->AddressOfFunctions);
        if (!namesRaw || !ordsRaw || !funcsRaw) goto done;
        if (namesRaw + exp->NumberOfNames * sizeof(DWORD) > len) goto done;
        if (ordsRaw  + exp->NumberOfNames * sizeof(WORD)  > len) goto done;
        DWORD *names = (DWORD *)(buf + namesRaw);
        WORD  *ords  = (WORD  *)(buf + ordsRaw);
        DWORD *funcs = (DWORD *)(buf + funcsRaw);
        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            DWORD nRaw = rva_to_raw(buf, len, names[i]);
            if (!nRaw || nRaw >= len) continue;
            const char *n = (const char *)buf + nRaw;
            if (strcmp(n, name) == 0) {
                WORD ord = ords[i];
                if (funcsRaw + (DWORD)(ord + 1) * sizeof(DWORD) <= len)
                    rva = funcs[ord];
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { rva = 0; }
done:
    free(buf);
    return rva;
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

static int run_inject(INJECTOR_CHANNEL *ch, unsigned int pid)
{
    unsigned char *buf = NULL;
    size_t len = 0;
    unsigned int entry_rva;
    char targetDll[MAX_PATH];

    resolve_target_dll(targetDll, sizeof(targetDll));
    if (!read_file_all(targetDll, &buf, &len)) return 2;
    if (len == 0 || len > INJECTOR_PAYLOAD_MAX) {
        printf("  payload size %zu out of range (max %u)\n", len, INJECTOR_PAYLOAD_MAX);
        free(buf); return 2;
    }
    if (ch->AbiVersion != 6) { printf("  driver ABI too old (need 6)\n"); free(buf); return 2; }

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

    entry_rva = find_export_rva(targetDll, "ManualEntry");
    if (entry_rva == 0) {
        printf("  FAIL: ManualEntry export not found in %s\n", targetDll);
        free(buf); return 2;
    }
    printf("  ManualEntry RVA resolved from %s -> 0x%X\n", targetDll, entry_rva);

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

    if (!send_payload(ch, buf, len)) { free(buf); return 3; }
    printf("  payload sent: %zu bytes; signalling CMD_MAP\n", len);

    InterlockedExchange(&ch->Cmd, INJECTOR_CMD_MAP);

    if (!wait_done(ch, 10000)) {
        printf("  timeout waiting for driver\n");
        free(buf); return 4;
    }
    long st = ch->CmdStatus;
    unsigned long long base = ch->RemoteBase;
    InterlockedExchange(&ch->Done, 0);

    printf("  driver status = 0x%08lX\n", (unsigned long)st);
    if (st == 0) {
        printf("  inject OK: base=0x%016llX\n", base);
        printf("  tls: slot=%ld status=0x%08lX threads_seeded=%ld\n",
               (long)ch->TlsSlot, (unsigned long)ch->TlsStatus,
               (long)ch->TlsThreadsSeeded);
        unsigned long long execVa = ch->RemoteBase + entry_rva;
        printf("  sending CMD_EXEC execVa=0x%016llX\n", execVa);
        ch->ExecutionVa = execVa;
        ch->HijackThreadId = 0;
        ch->HijackReserved = 0;
        InterlockedExchange(&ch->Done, 0);
        InterlockedExchange(&ch->Cmd, INJECTOR_CMD_EXEC);
        if (!wait_done(ch, 5000)) {
            printf("  CMD_EXEC timeout\n");
            free(buf); return 7;
        }
        long est = ch->CmdStatus;
        long tid = ch->HijackThreadId;
        InterlockedExchange(&ch->Done, 0);
        printf("  exec status=0x%08lX (%s) thread_id=%ld\n",
               (unsigned long)est, ntstatus_hint(est), tid);
        if (est != 0) { free(buf); return 8; }
        free(buf);
        return 0;
    } else {
        printf("  inject failed: status=0x%08lX (%s)\n",
               (unsigned long)st, ntstatus_hint(st));
        printf("  tls: slot=%ld status=0x%08lX threads_seeded=%ld\n",
               (long)ch->TlsSlot, (unsigned long)ch->TlsStatus,
               (long)ch->TlsThreadsSeeded);
        free(buf);
        return 5;
    }
}

int main(int argc, char **argv)
{
    int rc = 1;

    printf("Driver's Health:\n\n");
    print_channel_va();

    INJECTOR_CHANNEL *ch = attach_channel();

    if (ch != NULL && ch->AbiVersion != 6) {
        fprintf(stderr, "FATAL: channel ABI mismatch: driver reports %u, "
                        "client expects 6\n", ch->AbiVersion);
        goto out;
    }

    if (ch == NULL) {
        printf("  Driver is not mapped yet.\n");
        goto out;
    }

    if (argc <= 1) {
        rc = run_status(ch);
        rc = discover_target(ch);
    } else if (strcmp(argv[1], "--status") == 0) {
        rc = run_status(ch);
    } else if (strcmp(argv[1], "--inject") == 0) {
        const char *pidstr = NULL;
        for (int i = 2; i < argc; i++) {
            if (pidstr == NULL) pidstr = argv[i];
            else {
                printf("  usage: %s --inject <pid>\n", argv[0]);
                goto out;
            }
        }
        if (pidstr == NULL) {
            printf("  usage: %s --inject <pid>\n", argv[0]);
        } else {
            unsigned int pid = (unsigned int)strtoul(pidstr, NULL, 0);
            rc = run_inject(ch, pid);
        }
    } else {
        printf("  usage:\n");
        printf("    %s --status\n", argv[0]);
        printf("    %s --inject <pid>\n", argv[0]);
    }

out:
    wait_for_enter();
    return rc;
}
