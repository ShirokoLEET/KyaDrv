#pragma once
#include <ntddk.h>
#include <ntifs.h>
#include <wdm.h>
#include "import.hpp"

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;



BOOLEAN DeleteDriverFile(PUNICODE_STRING FilePath)
{
    NTSTATUS status;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;


    InitializeObjectAttributes(&objectAttributes,
        FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, NULL);


    status = ZwCreateFile(&fileHandle,
        DELETE | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DELETE_ON_CLOSE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "DeleteDriverFile: ZwCreateFile failed with status 0x%X\n", status);

        return FALSE;
    }

   
    ZwClose(fileHandle);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "DeleteDriverFile: File deletion scheduled successfully\n");
    return TRUE;
}


BOOLEAN DeleteSelfDriverFile(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "DeleteSelfDriverFile: Invalid driver object\n");
        return FALSE;
    }


    PLDR_DATA_TABLE_ENTRY ldrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!ldrEntry)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "DeleteSelfDriverFile: Failed to get LDR entry\n");
        return FALSE;
    }


    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[+]DeleteSelfDriverFile: Attempting to delete %wZ\n", &ldrEntry->FullDllName);

    return DeleteDriverFile(&ldrEntry->FullDllName);
}