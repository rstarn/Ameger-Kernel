#pragma once

#include <ntifs.h>

#ifndef AMEGER_CLIENT_IMAGE_NAME
#define AMEGER_CLIENT_IMAGE_NAME "Client.exe"
#endif

NTSTATUS AmegerChannelMapIntoProcess(PEPROCESS Process);
NTSTATUS AmegerChannelMapExisting(VOID);
