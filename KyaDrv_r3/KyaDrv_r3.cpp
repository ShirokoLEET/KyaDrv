// KyaDrv_r3.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
#include <Windows.h>
#include <cstdio>
#include <vector>
#include <string>
#include "../common.hpp"

namespace
{

std::vector<BYTE> ReadFileBytes(const std::wstring& path)
{
    std::vector<BYTE> buffer;

    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return buffer;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0)
    {
        CloseHandle(file);
        return buffer;
    }

    buffer.resize(static_cast<size_t>(size.QuadPart));
    DWORD bytes_read = 0;
    if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_read, nullptr) || bytes_read != buffer.size())
    {
        buffer.clear();
    }

    CloseHandle(file);
    return buffer;
}

void PrintResult(const KYADRV_MAP_RESULT& result)
{
    wprintf(L"[+] Driver mapped at 0x%p size 0x%llX, entry returned 0x%08X\n",
        reinterpret_cast<PVOID>(result.ImageBase),
        result.ImageSize,
        result.EntryStatus);
}

}

int wmain()
{
    const std::wstring driver_path = L".\\MyaDrv.sys";
    auto image = ReadFileBytes(driver_path);
    if (image.empty())
    {
        wprintf(L"[-] Failed to read %s\n", driver_path.c_str());
        return 1;
    }

    SIZE_T request_size = sizeof(KYADRV_MAP_REQUEST) - 1 + image.size();
    std::vector<BYTE> buffer(request_size);
    ZeroMemory(buffer.data(), buffer.size());
    auto request = reinterpret_cast<KYADRV_MAP_REQUEST*>(buffer.data());
    request->ImageSize = static_cast<ULONG>(image.size());
    request->Flags = KYADRV_MAP_FLAG_PASS_BASE_AS_PARAM1;
    request->Param1 = 0;
    request->Param2 = 0;
    wcsncpy_s(request->DriverName, L"MyaDrv.sys", _TRUNCATE);
    memcpy(request->Image, image.data(), image.size());

    HANDLE device = CreateFileW(KYADRV_USER_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] Failed to open %s (0x%08X)\n", KYADRV_USER_DEVICE_PATH, GetLastError());
        return 1;
    }

    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(device,
        IOCTL_KYADRV_MAP_DRIVER,
        request,
        static_cast<DWORD>(buffer.size()),
        request,
        static_cast<DWORD>(buffer.size()),
        &bytes_returned,
        nullptr);

    if (!ok)
    {
        wprintf(L"[-] DeviceIoControl failed 0x%08X\n", GetLastError());
        CloseHandle(device);
        return 1;
    }

    if (bytes_returned < sizeof(KYADRV_MAP_RESULT))
    {
        wprintf(L"[-] Unexpected output size %u\n", bytes_returned);
        CloseHandle(device);
        return 1;
    }

    KYADRV_MAP_RESULT result = {};
    memcpy(&result, buffer.data(), sizeof(result));
    PrintResult(result);

    CloseHandle(device);
    return 0;
}
