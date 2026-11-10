#pragma once

#include <ntifs.h>
#include "../Offsets.h"

#ifndef INJECTOR_CHANNEL_MAGIC
#define INJECTOR_CHANNEL_MAGIC 0xA7E3C1D9F042B685ULL
#endif

#define INJECTOR_CHANNEL_ABI_VERSION  6

#define INJECTOR_CHANNEL_HEADER_SIZE  0x1000
#define INJECTOR_CHANNEL_RING_SIZE    0x4000
#define INJECTOR_CHANNEL_TOTAL_SIZE   \
    (INJECTOR_CHANNEL_HEADER_SIZE + INJECTOR_CHANNEL_RING_SIZE)

#define INJECTOR_CMD_NONE         0
#define INJECTOR_CMD_VALIDATE     1
#define INJECTOR_CMD_MAP          2
#define INJECTOR_CMD_EXEC         3
#define INJECTOR_CMD_PROTECT_PID  4

#define INJECTOR_TLS_SLOT_INVALID  (-1)

typedef struct _INJECTOR_CHANNEL {
    UINT64  Magic;
    UINT32  AbiVersion;
    UINT32  _pad0;
    volatile LONG Head;
    volatile LONG Tail;
    UINT32  Pid;
    UINT32  Flags;

    volatile LONG Cmd;
    volatile LONG Done;
    volatile LONG CmdStatus;
    UINT32  PayloadSize;
    UINT32  PayloadReceived;
    UINT32  _pad1;
    volatile UINT64 RemoteBase;
    volatile UINT64 RelocCount;
    volatile UINT64 ImportDllCount;

    volatile LONG   TlsSlot;
    volatile LONG   TlsStatus;
    volatile LONG   TlsThreadsSeeded;
    UINT8           _pad2[4];

    volatile UINT64 ExecutionVa;
    volatile LONG   HijackThreadId;
    volatile LONG   HijackReserved;

    UINT32          ProtectedPid;
    volatile LONG   ObCallbackStatus;
    volatile UINT64 SelfTestAck;
    volatile UINT64 GadgetVa;

    volatile LONG   ObInitStatus;
    UINT32          _pad_obinit;
    UINT8   Ring[INJECTOR_CHANNEL_RING_SIZE];
} INJECTOR_CHANNEL, *PINJECTOR_CHANNEL;

C_ASSERT(FIELD_OFFSET(INJECTOR_CHANNEL, SelfTestAck) == 0x78);
C_ASSERT(FIELD_OFFSET(INJECTOR_CHANNEL, ObInitStatus) == 0x88);
C_ASSERT(FIELD_OFFSET(INJECTOR_CHANNEL, Ring) == 0x90);
C_ASSERT(sizeof(INJECTOR_CHANNEL) == 0x4090);

C_ASSERT(INJECTOR_CHANNEL_USER_VA == 0x00007FF000000000ULL);
C_ASSERT(INJECTOR_SELFTEST_ACK_OFFSET == FIELD_OFFSET(INJECTOR_CHANNEL, SelfTestAck));

#define INJECTOR_PAYLOAD_BUF_SIZE (16u * 1024u * 1024u)

NTSTATUS        InjectorChannelInitialize(VOID);
VOID            InjectorChannelDestroy(VOID);
PINJECTOR_CHANNEL InjectorChannelGet(VOID);
HANDLE          InjectorChannelGetSectionHandle(VOID);

NTSTATUS        InjectorMapSectionInSystemSpace(_In_ HANDLE SectionHandle,
                                              _Out_ PVOID *MappedBase,
                                              _Inout_ PSIZE_T ViewSize);
VOID            InjectorUnmapSectionInSystemSpace(_In_ PVOID MappedBase);
PUINT8          InjectorChannelGetPayloadBuffer(VOID);
UINT32          InjectorChannelGetPayloadBufferSize(VOID);
