#pragma once
#ifdef _KERNEL_MODE
#include <ntifs.h>
#else
#include <Windows.h>
#include <winternl.h>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#endif

#define KYADRV_USER_DEVICE_PATH L"\\\\.\\KyaDrv"

#ifndef IOCTL_KYADRV_MAP_DRIVER
#define IOCTL_KYADRV_MAP_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#define KYADRV_MAX_DRIVER_NAME 260
#define KYADRV_MAP_FLAG_FREE_AFTER_ENTRY 0x1
#define KYADRV_MAP_FLAG_PASS_BASE_AS_PARAM1 0x2

typedef struct _KYADRV_MAP_REQUEST
{
    ULONG ImageSize;
    ULONG Flags;
    ULONGLONG Param1;
    ULONGLONG Param2;
    WCHAR DriverName[KYADRV_MAX_DRIVER_NAME];
    UCHAR Image[1];
} KYADRV_MAP_REQUEST, *PKYADRV_MAP_REQUEST;

typedef struct _KYADRV_MAP_RESULT
{
    ULONGLONG ImageBase;
    ULONGLONG ImageSize;
    NTSTATUS EntryStatus;
} KYADRV_MAP_RESULT, *PKYADRV_MAP_RESULT;
