#include "loader.hpp"
#include "utils.hpp"
#include <ntifs.h>
#include <ntimage.h>
#pragma warning(push)
#pragma warning(disable: 4996)
namespace loader
{

struct KYADRV_MAPPED_DRIVER
{
    LIST_ENTRY Link;
    PVOID BaseAddress;
    SIZE_T ImageSize;
    UNICODE_STRING Name;
    NTSTATUS EntryStatus;
};

static LIST_ENTRY g_mapped_drivers;
static FAST_MUTEX g_mapped_lock;
static bool g_loader_initialized = false;

#define KYADRV_TAG 'pyaK'

static inline SIZE_T request_total_size(const KYADRV_MAP_REQUEST* request)
{
    return FIELD_OFFSET(KYADRV_MAP_REQUEST, Image) + request->ImageSize;
}

static void free_mapped_driver(_In_ KYADRV_MAPPED_DRIVER* entry)
{
    if (!entry)
        return;
    if (entry->BaseAddress)
        ExFreePoolWithTag(entry->BaseAddress, KYADRV_TAG);
    if (entry->Name.Buffer)
        ExFreePoolWithTag(entry->Name.Buffer, KYADRV_TAG);
    ExFreePoolWithTag(entry, KYADRV_TAG);
}

NTSTATUS initialize()
{
    InitializeListHead(&g_mapped_drivers);
    ExInitializeFastMutex(&g_mapped_lock);
    g_loader_initialized = true;
    return STATUS_SUCCESS;
}

void cleanup()
{
    if (!g_loader_initialized)
        return;

    ExAcquireFastMutex(&g_mapped_lock);
    while (!IsListEmpty(&g_mapped_drivers))
    {
        auto entry = CONTAINING_RECORD(RemoveHeadList(&g_mapped_drivers), KYADRV_MAPPED_DRIVER, Link);
        ExReleaseFastMutex(&g_mapped_lock);
        free_mapped_driver(entry);
        ExAcquireFastMutex(&g_mapped_lock);
    }
    ExReleaseFastMutex(&g_mapped_lock);
    g_loader_initialized = false;
}

static bool copy_sections(PVOID local_image, PVOID target_image, PIMAGE_NT_HEADERS64 nt_headers)
{
    RtlZeroMemory(target_image, nt_headers->OptionalHeader.SizeOfImage);
    RtlCopyMemory(target_image, local_image, nt_headers->OptionalHeader.SizeOfHeaders);

    auto section = IMAGE_FIRST_SECTION(nt_headers);
    for (USHORT i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
    {
        SIZE_T raw_size = section[i].SizeOfRawData;
        SIZE_T virtual_size = section[i].Misc.VirtualSize;
        SIZE_T copy_size = raw_size;

        if (copy_size == 0 && virtual_size == 0)
            continue;

        if (copy_size == 0)
            copy_size = virtual_size;

        if (section[i].VirtualAddress + copy_size > nt_headers->OptionalHeader.SizeOfImage)
            return false;

        PVOID target_section = reinterpret_cast<PUCHAR>(target_image) + section[i].VirtualAddress;
        PVOID source_section = reinterpret_cast<PUCHAR>(local_image) + section[i].PointerToRawData;

        // Clamp copy size to file buffer by using min(raw_size, virtual_size) when both are set
        if (raw_size && virtual_size)
            copy_size = min(raw_size, virtual_size);

        if (copy_size)
            RtlCopyMemory(target_section, source_section, copy_size);
    }

    return true;
}

static bool apply_relocations(PUCHAR image_base, PIMAGE_NT_HEADERS64 nt_headers, LONGLONG delta)
{
    if (delta == 0)
        return true;

    const auto& reloc_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.Size == 0)
        return false;

    auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(image_base + reloc_dir.VirtualAddress);
    auto reloc_end = reinterpret_cast<PUCHAR>(reloc) + reloc_dir.Size;

    while (reinterpret_cast<PUCHAR>(reloc) < reloc_end && reloc->SizeOfBlock)
    {
        ULONG entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        auto reloc_data = reinterpret_cast<PUSHORT>(reloc + 1);

        for (ULONG idx = 0; idx < entries; ++idx)
        {
            USHORT data = reloc_data[idx];
            USHORT type = data >> 12;
            USHORT offset = data & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64)
            {
                auto patch_address = reinterpret_cast<PULONG_PTR>(image_base + reloc->VirtualAddress + offset);
                *patch_address += delta;
            }
        }

        reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PUCHAR>(reloc) + reloc->SizeOfBlock);
    }

    return true;
}

static bool resolve_imports(PUCHAR image_base, PIMAGE_NT_HEADERS64 nt_headers)
{
    const auto& import_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size == 0)
        return true;

    auto import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image_base + import_dir.VirtualAddress);

    while (import_desc->Name)
    {
        const char* module_name = reinterpret_cast<const char*>(image_base + import_desc->Name);
        ULONG64 module_base = 0;
        ULONG module_size = 0;
        if (!utils::get_module_base_address(module_name, module_base, module_size))
            return false;

        auto original_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(image_base + import_desc->OriginalFirstThunk);
        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(image_base + import_desc->FirstThunk);

        if (!original_thunk)
            original_thunk = thunk;

        for (; original_thunk->u1.AddressOfData; ++original_thunk, ++thunk)
        {
            ULONG64 resolved = 0;
            if (IMAGE_SNAP_BY_ORDINAL64(original_thunk->u1.Ordinal))
            {
                if (!utils::get_module_export(module_base, nullptr, IMAGE_ORDINAL64(original_thunk->u1.Ordinal), true, resolved))
                    return false;
            }
            else
            {
                auto import_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image_base + original_thunk->u1.AddressOfData);
                if (!import_name)
                    return false;
                if (!utils::get_module_export(module_base, reinterpret_cast<const char*>(import_name->Name), 0, false, resolved))
                    return false;
            }

            thunk->u1.Function = resolved;
        }

        ++import_desc;
    }

    return true;
}


static NTSTATUS call_entry(PUCHAR image_base, PIMAGE_NT_HEADERS64 nt_headers, ULONGLONG param1, ULONGLONG param2)
{
    auto entry_address = reinterpret_cast<ULONGLONG>(image_base) + nt_headers->OptionalHeader.AddressOfEntryPoint;
    typedef NTSTATUS(NTAPI* PFN_PAYLOAD_ENTRY)(ULONGLONG, ULONGLONG);
    PFN_PAYLOAD_ENTRY entry_fn = reinterpret_cast<PFN_PAYLOAD_ENTRY>(entry_address);
    return entry_fn(param1, param2);
}

static BOOLEAN copy_driver_name_for_record(const KYADRV_MAP_REQUEST* request, UNICODE_STRING& target)
{
    SIZE_T name_len = 0;
    while (name_len < KYADRV_MAX_DRIVER_NAME - 1 && request->DriverName[name_len] != L'\0')
        ++name_len;
    if (name_len == 0)
    {
        RtlZeroMemory(&target, sizeof(target));
        return TRUE;
    }

    SIZE_T alloc_size = (name_len + 1) * sizeof(WCHAR);
    target.Buffer = static_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, alloc_size, KYADRV_TAG));
    if (!target.Buffer)
        return FALSE;
    RtlCopyMemory(target.Buffer, request->DriverName, alloc_size);
    target.Buffer[name_len] = L'\0';
    target.Length = static_cast<USHORT>(name_len * sizeof(WCHAR));
    target.MaximumLength = static_cast<USHORT>(alloc_size);
    return TRUE;
}

NTSTATUS map_image_from_request(const KYADRV_MAP_REQUEST* request, SIZE_T requestBufferSize, KYADRV_MAP_RESULT* result)
{
    if (!g_loader_initialized)
        return STATUS_DEVICE_NOT_READY;
    if (!request || !result)
        return STATUS_INVALID_PARAMETER;
    if (requestBufferSize < sizeof(KYADRV_MAP_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (request->ImageSize == 0)
        return STATUS_INVALID_PARAMETER;
    if (request_total_size(request) > requestBufferSize)
        return STATUS_BUFFER_TOO_SMALL;

    auto local_image = ExAllocatePoolWithTag(NonPagedPoolNx, request->ImageSize, KYADRV_TAG);
    if (!local_image)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(local_image, request->Image, request->ImageSize);

    auto nt_headers = utils::getNtHeader(local_image);
    if (!nt_headers || nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        ExFreePoolWithTag(local_image, KYADRV_TAG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    SIZE_T image_size = nt_headers->OptionalHeader.SizeOfImage;
    auto remote_image = ExAllocatePoolWithTag(NonPagedPoolExecute, image_size, KYADRV_TAG);
    if (!remote_image)
    {
        ExFreePoolWithTag(local_image, KYADRV_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!copy_sections(local_image, remote_image, nt_headers))
    {
        ExFreePoolWithTag(local_image, KYADRV_TAG);
        ExFreePoolWithTag(remote_image, KYADRV_TAG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    LONGLONG delta = reinterpret_cast<LONGLONG>(remote_image) - nt_headers->OptionalHeader.ImageBase;
    if (!apply_relocations(reinterpret_cast<PUCHAR>(remote_image), nt_headers, delta))
    {
        ExFreePoolWithTag(local_image, KYADRV_TAG);
        ExFreePoolWithTag(remote_image, KYADRV_TAG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (!resolve_imports(reinterpret_cast<PUCHAR>(remote_image), nt_headers))
    {
        ExFreePoolWithTag(local_image, KYADRV_TAG);
        ExFreePoolWithTag(remote_image, KYADRV_TAG);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    ULONGLONG first_param = (request->Flags & KYADRV_MAP_FLAG_PASS_BASE_AS_PARAM1) != 0 ?
        reinterpret_cast<ULONGLONG>(remote_image) : request->Param1;

    NTSTATUS entry_status = call_entry(reinterpret_cast<PUCHAR>(remote_image), nt_headers, first_param, request->Param2);

    result->ImageBase = reinterpret_cast<ULONGLONG>(remote_image);
    result->ImageSize = image_size;
    result->EntryStatus = entry_status;

    bool free_after_entry = (request->Flags & KYADRV_MAP_FLAG_FREE_AFTER_ENTRY) != 0;

    if (free_after_entry)
    {
        ExFreePoolWithTag(remote_image, KYADRV_TAG);
    }
    else
    {
        auto mapped_entry = static_cast<KYADRV_MAPPED_DRIVER*>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(KYADRV_MAPPED_DRIVER), KYADRV_TAG));
        if (!mapped_entry)
        {
            ExFreePoolWithTag(remote_image, KYADRV_TAG);
            ExFreePoolWithTag(local_image, KYADRV_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(mapped_entry, sizeof(*mapped_entry));
        mapped_entry->BaseAddress = remote_image;
        mapped_entry->ImageSize = image_size;
        mapped_entry->EntryStatus = entry_status;
        if (!copy_driver_name_for_record(request, mapped_entry->Name))
        {
            mapped_entry->Name.Buffer = nullptr;
            mapped_entry->Name.Length = 0;
            mapped_entry->Name.MaximumLength = 0;
        }

        ExAcquireFastMutex(&g_mapped_lock);
        InsertHeadList(&g_mapped_drivers, &mapped_entry->Link);
        ExReleaseFastMutex(&g_mapped_lock);
    }

    ExFreePoolWithTag(local_image, KYADRV_TAG);
    return STATUS_SUCCESS;
}

}
