#include <ntifs.h>
#include <ntddk.h>

#include "utils.hpp"
#include "trace.hpp"
#include "cleaner.hpp"


#define DRIVER_PREFIX "KyaDrv: "

#ifndef KYADRV_TAG
#define KYADRV_TAG 'ayK'
#endif

static const wchar_t kKyaDrvName[] = L"KyaDrv.sys";

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	LARGE_INTEGER interval;
	interval.QuadPart = -10000; 
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
	trace::cleanup();
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, DRIVER_PREFIX "Driver unloaded successfully\n");

}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	//UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, DRIVER_PREFIX "DriverEntry -> clear self trace\n");
	DeleteSelfDriverFile(DriverObject);

	wchar_t name_buf[260] = { 0 };
	const wchar_t* target_name = kKyaDrvName;
	PLDR_DATA_TABLE_ENTRY ldrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	if (ldrEntry && ldrEntry->BaseDllName.Buffer && ldrEntry->BaseDllName.Length > 0)
	{
		size_t count = ldrEntry->BaseDllName.Length / sizeof(wchar_t);
		const size_t buf_cap = RTL_NUMBER_OF(name_buf);
		if (count >= buf_cap)
			count = buf_cap - 1;
		RtlCopyMemory(name_buf, ldrEntry->BaseDllName.Buffer, count * sizeof(wchar_t));
		name_buf[count] = L'\0';
		target_name = name_buf;
	}

	{
		auto ok = trace::clear_cache_by_name(target_name);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID,
			ok ? DPFLTR_INFO_LEVEL : DPFLTR_ERROR_LEVEL,
			DRIVER_PREFIX "clear_cache_by_name(%ws): %s\n",
			target_name, ok ? "success" : "failed");
	}
	{
		auto ok = trace::clear_unloaded_driver(target_name);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID,
			ok ? DPFLTR_INFO_LEVEL : DPFLTR_ERROR_LEVEL,
			DRIVER_PREFIX "clear_unloaded_driver(%ws): %s\n",
			target_name, ok ? "success" : "failed");
	}
	{
		auto ok = trace::clear_hash_bucket_list(target_name);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID,
			ok ? DPFLTR_INFO_LEVEL : DPFLTR_ERROR_LEVEL,
			DRIVER_PREFIX "clear_hash_bucket_list(%ws): %s\n",
			target_name, ok ? "success" : "failed");
	}
	{
		auto ok = trace::clear_ci_ea_cache_lookaside_list();
		DbgPrintEx(DPFLTR_IHVDRIVER_ID,
			ok ? DPFLTR_INFO_LEVEL : DPFLTR_ERROR_LEVEL,
			DRIVER_PREFIX "clear_ci_ea_cache_lookaside_list: %s\n",
			ok ? "success" : "failed");
	}


	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}





