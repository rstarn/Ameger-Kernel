#pragma once

#include <ntifs.h>
#include "../Offsets.h"

#ifndef AMEGER_CHANNEL_MAGIC
#define AMEGER_CHANNEL_MAGIC 0xA7E3C1D9F042B685ULL
#endif

#define AMEGER_CHANNEL_ABI_VERSION  6

#define AMEGER_CHANNEL_HEADER_SIZE  0x1000
#define AMEGER_CHANNEL_RING_SIZE    0x4000
#define AMEGER_CHANNEL_TOTAL_SIZE   \
    (AMEGER_CHANNEL_HEADER_SIZE + AMEGER_CHANNEL_RING_SIZE)

#define AMEGER_CMD_NONE         0
#define AMEGER_CMD_VALIDATE     1
#define AMEGER_CMD_MAP          2
#define AMEGER_CMD_EXEC         3
#define AMEGER_CMD_PROTECT_PID  4

#define AMEGER_TLS_SLOT_INVALID  (-1)

typedef struct _AMEGER_CHANNEL {
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
    UINT8   Ring[AMEGER_CHANNEL_RING_SIZE];
} AMEGER_CHANNEL, *PAMEGER_CHANNEL;

C_ASSERT(FIELD_OFFSET(AMEGER_CHANNEL, SelfTestAck) == 0x78);
C_ASSERT(FIELD_OFFSET(AMEGER_CHANNEL, ObInitStatus) == 0x88);
C_ASSERT(FIELD_OFFSET(AMEGER_CHANNEL, Ring) == 0x90);
C_ASSERT(sizeof(AMEGER_CHANNEL) == 0x4090);

C_ASSERT(AMEGER_CHANNEL_USER_VA == 0x00007FF000000000ULL);
C_ASSERT(AMEGER_SELFTEST_ACK_OFFSET == FIELD_OFFSET(AMEGER_CHANNEL, SelfTestAck));

#define AMEGER_PAYLOAD_BUF_SIZE (16u * 1024u * 1024u)

NTSTATUS        AmegerChannelInitialize(VOID);
VOID            AmegerChannelDestroy(VOID);
PAMEGER_CHANNEL AmegerChannelGet(VOID);
HANDLE          AmegerChannelGetSectionHandle(VOID);

NTSTATUS        AmegerMapSectionInSystemSpace(_In_ HANDLE SectionHandle,
                                              _Out_ PVOID *MappedBase,
                                              _Inout_ PSIZE_T ViewSize);
VOID            AmegerUnmapSectionInSystemSpace(_In_ PVOID MappedBase);
PUINT8          AmegerChannelGetPayloadBuffer(VOID);
UINT32          AmegerChannelGetPayloadBufferSize(VOID);
