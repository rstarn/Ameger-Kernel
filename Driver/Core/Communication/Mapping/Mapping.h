#pragma once

#include <ntifs.h>

#ifndef INJECTOR_CLIENT_IMAGE_NAME
#define INJECTOR_CLIENT_IMAGE_NAME "Client.exe"
#endif

NTSTATUS InjectorChannelMapIntoProcess(PEPROCESS Process);
NTSTATUS InjectorChannelMapExisting(VOID);
