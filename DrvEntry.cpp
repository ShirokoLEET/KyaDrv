#include <ntifs.h>
#include "IoCreateDriver.h"

#define DRIVER_PREFIX "KyaDrv: "

// 可选：自定义池标签
#ifndef KYADRV_TAG
#define KYADRV_TAG 'ayK' // 'Kya' 的反序字节序
#endif

// 全局符号链接名称，供 DriverEntry 与 DriverUnload 共享
static UNICODE_STRING g_SymLink = RTL_CONSTANT_STRING(L"\\DosDevices\\KyaDrv");

// 完成 IRP 的小工具函数
static NTSTATUS CompleteRequest(_In_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Information = 0) {
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

// 不支持的缺省分发
static NTSTATUS KyaDrvDispatchUnsupported(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, DRIVER_PREFIX "Unsupported IRP: 0x%X\n",
        IoGetCurrentIrpStackLocation(Irp)->MajorFunction);
    return CompleteRequest(Irp, STATUS_INVALID_DEVICE_REQUEST);
}

// Create/Close 返回成功
static NTSTATUS KyaDrvDispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteRequest(Irp, STATUS_SUCCESS);
}

// DeviceIoControl 缺省为不支持（后续可在此实现 IOCTL）
static NTSTATUS KyaDrvDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    return CompleteRequest(Irp, STATUS_INVALID_DEVICE_REQUEST);
}

extern "C"
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DriverObject);

    // 删除符号链接与设备
    IoDeleteSymbolicLink(&g_SymLink);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, DRIVER_PREFIX "Unload\n");
}

static NTSTATUS __fastcall KyaDrvInitialize(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, DRIVER_PREFIX "KyaDrvInitialize via IoCreateDriver\n");

    // 设置缺省分发
    for (UINT32 i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) {
        DriverObject->MajorFunction[i] = KyaDrvDispatchUnsupported;
    }

    // 设置必要分发
    DriverObject->MajorFunction[IRP_MJ_CREATE] = KyaDrvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KyaDrvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KyaDrvDispatchDeviceControl;

    // 卸载例程
    DriverObject->DriverUnload = DriverUnload;

    // 创建设备与符号链接（如需 IOCTL 通道可取消注释）
    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_OBJECT deviceObject = nullptr;
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\KyaDrv");
    
    status = IoCreateDevice(
        DriverObject,
        0,                  // 设备扩展大小
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRIVER_PREFIX "IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }
    
    deviceObject->Flags |= DO_DIRECT_IO; // 或 DO_BUFFERED_IO，按需选择
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    
    status = IoCreateSymbolicLink(&g_SymLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, DRIVER_PREFIX "IoCreateSymbolicLink failed: 0x%08X\n", status);
        return status;
    }

    return STATUS_SUCCESS;
}

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, DRIVER_PREFIX "DriverEntry -> IoCreateDriver proxy\n");
    return IoCreateDriver(KyaDrvInitialize);
}
