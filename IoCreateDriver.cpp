#include "IoCreateDriver.h"

extern "C" {

static NTSTATUS NTAPI IopInvalidDeviceRequest(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS __fastcall IoCreateDriver(
    _In_ NTSTATUS(__fastcall* EntryPoint)(_In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING)
) {
    HANDLE drv_handle = nullptr;
    USHORT name_length = 0;
    WCHAR name_buffer[100] = {};
    PDRIVER_OBJECT drv_obj = nullptr;
    OBJECT_ATTRIBUTES obj_attribs = {};
    UNICODE_STRING local_drv_name = {};
    UNICODE_STRING service_key_name = {};
    NTSTATUS status = STATUS_SUCCESS;
    const ULONG obj_size = sizeof(DRIVER_OBJECT) + sizeof(EXTENDED_DRIVER_EXTENSION);

    name_length = (USHORT)swprintf(name_buffer, L"\\Driver\\%08u", (ULONG)KeQueryUnbiasedInterruptTime());
    local_drv_name.Length = name_length * sizeof(WCHAR);
    local_drv_name.MaximumLength = local_drv_name.Length + sizeof(WCHAR);
    local_drv_name.Buffer = name_buffer;

    InitializeObjectAttributes(&obj_attribs, &local_drv_name, OBJ_PERMANENT | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    status = ObCreateObject(KernelMode, IoDriverObjectType, &obj_attribs, KernelMode, nullptr, obj_size, 0, 0, reinterpret_cast<PVOID*>(&drv_obj));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(drv_obj, obj_size);
    drv_obj->Type = IO_TYPE_DRIVER;
    drv_obj->Size = sizeof(DRIVER_OBJECT);
    drv_obj->Flags = DRVO_BUILTIN_DRIVER;
    drv_obj->DriverExtension = reinterpret_cast<PDRIVER_EXTENSION>(drv_obj + 1);
    drv_obj->DriverExtension->DriverObject = drv_obj;
    drv_obj->DriverInit = EntryPoint;

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        drv_obj->MajorFunction[i] = IopInvalidDeviceRequest;
    }

    service_key_name.MaximumLength = local_drv_name.Length + sizeof(WCHAR);
    service_key_name.Buffer = static_cast<PWCH>(ExAllocatePool2(POOL_FLAG_PAGED, service_key_name.MaximumLength, (ULONG)KeQueryUnbiasedInterruptTime()));
    if (!service_key_name.Buffer) {
        ObMakeTemporaryObject(drv_obj);
        ObfDereferenceObject(drv_obj);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyUnicodeString(&service_key_name, &local_drv_name);
    service_key_name.Buffer[service_key_name.Length / sizeof(WCHAR)] = UNICODE_NULL;
    drv_obj->DriverExtension->ServiceKeyName = service_key_name;

    drv_obj->DriverName.MaximumLength = local_drv_name.Length;
    drv_obj->DriverName.Buffer = static_cast<PWCH>(ExAllocatePool2(POOL_FLAG_PAGED, drv_obj->DriverName.MaximumLength, (ULONG)KeQueryUnbiasedInterruptTime()));
    if (!drv_obj->DriverName.Buffer) {
        ObMakeTemporaryObject(drv_obj);
        ObfDereferenceObject(drv_obj);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyUnicodeString(&drv_obj->DriverName, &local_drv_name);

    status = ObInsertObject(drv_obj, nullptr, FILE_READ_DATA, 0, nullptr, &drv_handle);
    if (NT_SUCCESS(status)) {
        ZwClose(drv_handle);
    } else {
        ObMakeTemporaryObject(drv_obj);
        ObfDereferenceObject(drv_obj);
        return status;
    }

    status = EntryPoint(drv_obj, nullptr);
    if (!NT_SUCCESS(status)) {
        ObMakeTemporaryObject(drv_obj);
        ObfDereferenceObject(drv_obj);
        return status;
    }

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (!drv_obj->MajorFunction[i]) {
            drv_obj->MajorFunction[i] = IopInvalidDeviceRequest;
        }
    }

    return status;
}

} // extern "C"

