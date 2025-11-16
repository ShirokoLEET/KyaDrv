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

BOOLEAN DeleteFile(PUNICODE_STRING FilePath)
{
	NTSTATUS ntstatus = NULL;
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES obj = { 0 };
	IO_STATUS_BLOCK IostaBlc = { 0 };
	PFILE_OBJECT pFileObj = NULL;

	InitializeObjectAttributes(&obj, FilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	
	ntstatus = NtCreateFile(
		&hFile,
		FILE_READ_ACCESS,
		&obj,
		&IostaBlc,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE,
		NULL,
		NULL
	);

	if (!NT_SUCCESS(ntstatus))
	{
		return FALSE;
	}

	ntstatus = ObReferenceObjectByHandle(
		hFile,
		FILE_ANY_ACCESS,
		*IoFileObjectType,
		KernelMode,
		(PVOID*)&pFileObj, 
		NULL
	);
	
	if (!NT_SUCCESS(ntstatus) || pFileObj == NULL)
	{

		return FALSE;
	}

	

	pFileObj->DeletePending = 0;
	pFileObj->DeleteAccess  = 1;
	//pFileObj->SharedDelete  = 1;
	pFileObj->SectionObjectPointer->DataSectionObject  = NULL;
	pFileObj->SectionObjectPointer->ImageSectionObject = NULL;
	//pFileObj->SectionObjectPointer->SharedCacheMap	   = NULL;
	MmFlushImageSection(pFileObj->SectionObjectPointer, MmFlushForDelete);

	ntstatus = ZwDeleteFile(&obj);
	if (pFileObj != NULL)
	{
		ObDereferenceObject(pFileObj);
	}
	ZwClose(hFile);
	return NT_SUCCESS(ntstatus) ? TRUE : FALSE;
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


    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[+]DeleteSelfDriverFile: Attempting to delete %wZ\n", &ldrEntry->FullDllName);

    return DeleteFile(&ldrEntry->FullDllName);
}