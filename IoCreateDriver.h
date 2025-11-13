#pragma once

// Minimal re-implementation of IoCreateDriver that can be bundled with
// manual-mapped drivers to obtain a valid DRIVER_OBJECT/dispatch table.
#include <ntifs.h>
#include <ntstrsafe.h>
#include <windef.h>

extern "C" {

__declspec(dllimport) POBJECT_TYPE IoDriverObjectType;

NTSTATUS
NTAPI
ObCreateObject(
    _In_opt_ KPROCESSOR_MODE ProbeMode,
    _In_ POBJECT_TYPE Type,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _In_ ULONG ObjectSize,
    _In_opt_ ULONG PagedPoolCharge,
    _In_opt_ ULONG NonPagedPoolCharge,
    _Out_ PVOID* Object
);

typedef struct _IO_CLIENT_EXTENSION {
    struct _IO_CLIENT_EXTENSION* NextExtension;
    PVOID ClientIdentificationAddress;
} IO_CLIENT_EXTENSION, *PIO_CLIENT_EXTENSION;

typedef struct _EXTENDED_DRIVER_EXTENSION {
    struct _DRIVER_OBJECT* DriverObject;
    PDRIVER_ADD_DEVICE AddDevice;
    ULONG Count;
    UNICODE_STRING ServiceKeyName;
    PIO_CLIENT_EXTENSION ClientDriverExtension;
    PFS_FILTER_CALLBACKS FsFilterCallbacks;
} EXTENDED_DRIVER_EXTENSION, *PEXTENDED_DRIVER_EXTENSION;

NTSTATUS
__fastcall
IoCreateDriver(
    _In_ NTSTATUS(__fastcall* EntryPoint)(_In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING)
    );

} // extern "C"

