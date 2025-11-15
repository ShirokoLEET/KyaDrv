#include <ntifs.h>
#include <ntddk.h>

#include "utils.hpp"
#include "trace.hpp"

#define DRIVER_PREFIX "KyaDrv: "

#ifndef KYADRV_TAG
#define KYADRV_TAG 'ayK'
#endif

static const wchar_t kKyaDrvName[] = L"KyaDrv.sys";

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, DRIVER_PREFIX "DriverEntry -> clear self trace\n");

	trace::clear_cache_by_name(kKyaDrvName);
	trace::clear_unloaded_driver(kKyaDrvName);
	trace::clear_hash_bucket_list(kKyaDrvName);
	//trace::clear_ci_ea_cache_lookaside_list();

	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}
