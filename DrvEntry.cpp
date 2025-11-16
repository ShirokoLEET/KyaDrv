#include <ntifs.h>
#include <ntddk.h>

#include "utils.hpp"
#include "common.hpp"
#include "trace.hpp"
#include "cleaner.hpp"
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

DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH KyaDrvIrpCreateClose;
DRIVER_DISPATCH KyaDrvDeviceControl;

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	LARGE_INTEGER interval;
	interval.QuadPart = -10000;
	KeDelayExecutionThread(KernelMode, FALSE, &interval);

	loader::cleanup();

	if (g_SymbolicLinkName.Buffer)
	{
		IoDeleteSymbolicLink(&g_SymbolicLinkName);
	}

	if (g_DeviceObject)
	{
		IoDeleteDevice(g_DeviceObject);
		g_DeviceObject = nullptr;
	}

	ResetDeviceStrings();
	trace::cleanup();
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, DRIVER_PREFIX "Driver unloaded successfully\n");
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, DRIVER_PREFIX "DriverEntry -> clear self trace\n");
	DeleteSelfDriverFile(DriverObject);

	wchar_t name_buf[260] = { 0 };
	wchar_t full_name_buf[512] = { 0 };
	const wchar_t* target_name = kKyaDrvName;
	const wchar_t* target_full_name = nullptr;
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
	if (ldrEntry && ldrEntry->FullDllName.Buffer && ldrEntry->FullDllName.Length > 0)
	{
		size_t count = ldrEntry->FullDllName.Length / sizeof(wchar_t);
		const size_t buf_cap = RTL_NUMBER_OF(full_name_buf);
		if (count >= buf_cap)
			count = buf_cap - 1;
		RtlCopyMemory(full_name_buf, ldrEntry->FullDllName.Buffer, count * sizeof(wchar_t));
		full_name_buf[count] = L'\0';
		target_full_name = full_name_buf;
	}

	trace::clear_cache_by_name(target_name, target_full_name);
	trace::clear_unloaded_driver(target_name, target_full_name);
	trace::clear_hash_bucket_list(target_name, target_full_name);
	trace::clear_ci_ea_cache_lookaside_list();

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
			if (request->DriverName[0] != L'\0')
			{	
				trace::clear_cache_by_name(request->DriverName, nullptr);
				trace::clear_unloaded_driver(request->DriverName, nullptr);
				trace::clear_hash_bucket_list(request->DriverName, nullptr);
			}

			RtlCopyMemory(request, &result, sizeof(result));
			information = sizeof(result);
		}
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

