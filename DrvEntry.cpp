#include <ntifs.h>
#include <ntddk.h>

#include "common.hpp" 
#include "utils.hpp"
#include "trace.hpp"
#include "loader.hpp"

#pragma warning(push)
#pragma warning(disable: 4996)
#define DRIVER_PREFIX "KyaDrv: "

#ifndef KYADRV_TAG
#define KYADRV_TAG 'ayK'
#endif

namespace
{
	PDEVICE_OBJECT g_DeviceObject = nullptr;
	UNICODE_STRING g_DeviceName = {};
	UNICODE_STRING g_SymbolicLinkName = {};

	void FreeUnicodeStringBuffer(_Inout_ UNICODE_STRING& value)
	{
		if (!value.Buffer)
			return;

		ExFreePoolWithTag(value.Buffer, KYADRV_TAG);
		value.Buffer = nullptr;
		value.Length = 0;
		value.MaximumLength = 0;
	}

	void ResetDeviceStrings()
	{
		FreeUnicodeStringBuffer(g_DeviceName);
		FreeUnicodeStringBuffer(g_SymbolicLinkName);
	}

	NTSTATUS AllocatePrefixedName(_In_ const UNICODE_STRING& prefix, _In_ const UNICODE_STRING& baseName, _Out_ UNICODE_STRING& target)
	{
		const USHORT total_length = prefix.Length + baseName.Length;

		target.MaximumLength = total_length + sizeof(WCHAR);
		target.Buffer = static_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, target.MaximumLength, KYADRV_TAG));
		if (!target.Buffer)
		{
			target.Length = 0;
			target.MaximumLength = 0;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(target.Buffer, target.MaximumLength);
		RtlCopyMemory(target.Buffer, prefix.Buffer, prefix.Length);
		RtlCopyMemory(reinterpret_cast<PUCHAR>(target.Buffer) + prefix.Length, baseName.Buffer, baseName.Length);
		target.Length = total_length;
		return STATUS_SUCCESS;
	}

	NTSTATUS BuildDeviceStrings(_In_ PDRIVER_OBJECT DriverObject)
	{
		UNICODE_STRING default_name = RTL_CONSTANT_STRING(L"KyaDrv");
		UNICODE_STRING base_name = default_name;

		if (DriverObject->DriverName.Buffer && DriverObject->DriverName.Length > 0)
		{
			base_name = DriverObject->DriverName;
			const USHORT char_count = base_name.Length / sizeof(WCHAR);
			USHORT start_index = 0;
			for (USHORT i = 0; i < char_count; ++i)
			{
				if (base_name.Buffer[i] == L'\\')
					start_index = static_cast<USHORT>(i + 1);
			}

			if (start_index < char_count)
			{
				base_name.Buffer += start_index;
				base_name.Length -= start_index * sizeof(WCHAR);
				base_name.MaximumLength = base_name.Length;
			}

			if (base_name.Length == 0)
				base_name = default_name;
		}

		const UNICODE_STRING device_prefix = RTL_CONSTANT_STRING(L"\\Device\\");
		const UNICODE_STRING dosdev_prefix = RTL_CONSTANT_STRING(L"\\DosDevices\\");

		NTSTATUS status = AllocatePrefixedName(device_prefix, base_name, g_DeviceName);
		if (!NT_SUCCESS(status))
			return status;

		status = AllocatePrefixedName(dosdev_prefix, base_name, g_SymbolicLinkName);
		if (!NT_SUCCESS(status))
		{
			FreeUnicodeStringBuffer(g_DeviceName);
			return status;
		}

		return STATUS_SUCCESS;
	}
}

static const wchar_t kKyaDrvName[] = L"KyaDrv.sys";
static const wchar_t kNeacSafeName[] = L"NeacSafe64.sys";

DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH KyaDrvIrpCreateClose;
DRIVER_DISPATCH KyaDrvDeviceControl;

VOID CleanupWorkItemRoutine(_In_ PVOID Parameter)
{
	PWORK_QUEUE_ITEM workItem = (PWORK_QUEUE_ITEM)Parameter;
	PVOID context = workItem->Parameter;

	if (context) {
		PDEVICE_OBJECT deviceObject = *(PDEVICE_OBJECT*)context;
		if (deviceObject) {
			if (g_SymbolicLinkName.Buffer) {
				IoDeleteSymbolicLink(&g_SymbolicLinkName);
			}
			IoDeleteDevice(deviceObject);
		}
		ExFreePoolWithTag(context, KYADRV_TAG);
	}

	ExFreePoolWithTag(workItem, KYADRV_TAG);
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	KIRQL currentIrql = KeGetCurrentIrql();

	if (currentIrql > PASSIVE_LEVEL) {
	
		PWORK_QUEUE_ITEM workItem = (PWORK_QUEUE_ITEM)ExAllocatePoolWithTag(
			NonPagedPoolNx, sizeof(WORK_QUEUE_ITEM), KYADRV_TAG);

		if (workItem) {
			PVOID context = ExAllocatePoolWithTag(NonPagedPoolNx,
				sizeof(PDEVICE_OBJECT) + sizeof(UNICODE_STRING), KYADRV_TAG);

			if (context) {
				PDEVICE_OBJECT* devicePtr = (PDEVICE_OBJECT*)context;
				UNICODE_STRING* symLinkPtr = (UNICODE_STRING*)((PUCHAR)context + sizeof(PDEVICE_OBJECT));

				*devicePtr = g_DeviceObject;
				RtlCopyMemory(symLinkPtr, &g_SymbolicLinkName, sizeof(UNICODE_STRING));

				ExInitializeWorkItem(workItem, CleanupWorkItemRoutine, context);
				ExQueueWorkItem(workItem, DelayedWorkQueue);

				
				LARGE_INTEGER interval;
				interval.QuadPart = -1000000; 
				KeDelayExecutionThread(KernelMode, FALSE, &interval);
			}
			else {
				ExFreePoolWithTag(workItem, KYADRV_TAG);
			}
		}
	}
	else {
		
		if (g_SymbolicLinkName.Buffer) {
			IoDeleteSymbolicLink(&g_SymbolicLinkName);
		}

		if (g_DeviceObject) {
			IoDeleteDevice(g_DeviceObject);
			g_DeviceObject = nullptr;
		}
	}

	
	loader::cleanup();
	trace::cleanup();
	ResetDeviceStrings();

	DbgPrintEx(DPFLTR_IHVDRIVER_ID,0,
		DRIVER_PREFIX "[KyaDrv] Driver unloaded successfully at IRQL: %d\n", currentIrql);
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	wchar_t name_buf[260] = { 0 };
	wchar_t full_name_buf[512] = { 0 };
	const wchar_t* target_name = kKyaDrvName;
	const wchar_t* target_full_name = nullptr;


	PLDR_DATA_TABLE_ENTRY ldrEntry = nullptr;
	if (DriverObject && DriverObject->DriverSection)
	{
		ldrEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);

	
		if (MmIsAddressValid(ldrEntry))
		{
			
			if (MmIsAddressValid(&ldrEntry->BaseDllName) &&
				ldrEntry->BaseDllName.Buffer &&
				ldrEntry->BaseDllName.Length > 0 &&
				MmIsAddressValid(ldrEntry->BaseDllName.Buffer))
			{
				size_t count = ldrEntry->BaseDllName.Length / sizeof(wchar_t);
				const size_t buf_cap = RTL_NUMBER_OF(name_buf);
				if (count >= buf_cap)
					count = buf_cap - 1;

			
				if (count > 0 && count < buf_cap)
				{
					__try
					{
						RtlCopyMemory(name_buf, ldrEntry->BaseDllName.Buffer, count * sizeof(wchar_t));
						name_buf[count] = L'\0';
						target_name = name_buf;
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, DRIVER_PREFIX "Failed to copy base DLL name\n");
					}
				}
			}

		
			if (MmIsAddressValid(&ldrEntry->FullDllName) &&
				ldrEntry->FullDllName.Buffer &&
				ldrEntry->FullDllName.Length > 0 &&
				MmIsAddressValid(ldrEntry->FullDllName.Buffer))
			{
				size_t count = ldrEntry->FullDllName.Length / sizeof(wchar_t);
				const size_t buf_cap = RTL_NUMBER_OF(full_name_buf);
				if (count >= buf_cap)
					count = buf_cap - 1;

				if (count > 0 && count < buf_cap)
				{
					__try
					{
						RtlCopyMemory(full_name_buf, ldrEntry->FullDllName.Buffer, count * sizeof(wchar_t));
						full_name_buf[count] = L'\0';
						target_full_name = full_name_buf;
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, DRIVER_PREFIX "Failed to copy full DLL name\n");
					}
				}
			}
		}
	}

	NTSTATUS status = BuildDeviceStrings(DriverObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRIVER_PREFIX "Failed to build device names 0x%X\n", status);
		return status;
	}

	status = IoCreateDevice(DriverObject, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRIVER_PREFIX "IoCreateDevice failed 0x%X\n", status);
		ResetDeviceStrings();
		return status;
	}

	g_DeviceObject->Flags |= DO_BUFFERED_IO;
	g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	status = IoCreateSymbolicLink(&g_SymbolicLinkName, &g_DeviceName);
	if (!NT_SUCCESS(status))
	{
		ResetDeviceStrings();
		IoDeleteDevice(g_DeviceObject);
		g_DeviceObject = nullptr;
		return status;
	}

	status = loader::initialize();
	if (!NT_SUCCESS(status))
	{
		IoDeleteSymbolicLink(&g_SymbolicLinkName);
		ResetDeviceStrings();
		IoDeleteDevice(g_DeviceObject);
		g_DeviceObject = nullptr;
		return status;
	}

	for (UCHAR i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
	{
		DriverObject->MajorFunction[i] = KyaDrvIrpCreateClose;
	}
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KyaDrvDeviceControl;
	DriverObject->DriverUnload = DriverUnload;


	return STATUS_SUCCESS;
}

NTSTATUS KyaDrvIrpCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS KyaDrvDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG_PTR information = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_KYADRV_MAP_DRIVER:
    {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(loader::KYADRV_MAP_REQUEST))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto request = reinterpret_cast<loader::KYADRV_MAP_REQUEST*>(Irp->AssociatedIrp.SystemBuffer);
		loader::KYADRV_MAP_RESULT result{};
		status = loader::map_image_from_request(request, stack->Parameters.DeviceIoControl.InputBufferLength, &result);
        if (NT_SUCCESS(status))
        {
            RtlCopyMemory(request, &result, sizeof(result));
            information = sizeof(result);
        }
        break;
    }
    case IOCTL_KYADRV_CLEAN_TRACES:
    {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(KYADRV_CLEAN_REQUEST))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto clean_req = reinterpret_cast<KYADRV_CLEAN_REQUEST*>(Irp->AssociatedIrp.SystemBuffer);

        if (clean_req->VulnerableDriver[0] != L'\0')
        {
            trace::clear_cache_by_name(clean_req->VulnerableDriver, nullptr);
            trace::clear_unloaded_driver(clean_req->VulnerableDriver, nullptr);
            trace::clear_hash_bucket_list(clean_req->VulnerableDriver, nullptr);
            //trace::clear_wdfilter_driver_list(clean_req->VulnerableDriver, nullptr);
        }

        if (clean_req->CheatDriver[0] != L'\0')
        {
            trace::clear_cache_by_name(clean_req->CheatDriver, nullptr);
            trace::clear_unloaded_driver(clean_req->CheatDriver, nullptr);
            trace::clear_hash_bucket_list(clean_req->CheatDriver, nullptr);
            //trace::clear_wdfilter_driver_list(clean_req->CheatDriver, nullptr);
        }

        // CI cache 只需清一次
        trace::clear_ci_ea_cache_lookaside_list();

        status = STATUS_SUCCESS;
        information = sizeof(KYADRV_CLEAN_REQUEST);
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

