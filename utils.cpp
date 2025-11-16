#include "utils.hpp"

extern "C" {
#include <ntifs.h>
#include <ntimage.h>
}

#pragma warning(push)
#pragma warning(disable: 4996)

namespace utils
{
    PIMAGE_NT_HEADERS getNtHeader(PVOID base)
    {
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PUCHAR>(base) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        return nt;
    }

    bool get_module_base_address(const char* name, unsigned long long& addr, unsigned long& size)
    {
        unsigned long need_size = 0;
        ZwQuerySystemInformation(11, &need_size, 0, &need_size);
        if (need_size == 0) return false;

        const unsigned long tag = 'Util';
        auto sys_mods = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePoolWithTag(NonPagedPool, need_size, tag));
        if (!sys_mods) return false;

        NTSTATUS status = ZwQuerySystemInformation(11, sys_mods, need_size, 0);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(sys_mods, tag);
            return false;
        }

        addr = 0;
        size = 0;
        for (unsigned long long i = 0; i < sys_mods->ulModuleCount; i++)
        {
            const SYSTEM_MODULE& mod = sys_mods->Modules[i];
            if (strstr(mod.ImageName, name))
            {
                addr = reinterpret_cast<unsigned long long>(mod.Base);
                size = static_cast<unsigned long>(mod.Size);
                break;
            }
        }

        ExFreePoolWithTag(sys_mods, tag);
        return addr && size;
    }

    bool pattern_check(const char* data, const char* pattern, const char* mask)
    {
        size_t len = strlen(mask);
        for (size_t i = 0; i < len; i++)
        {
            if (data[i] == pattern[i] || mask[i] == '?')
                continue;
            else
                return false;
        }
        return true;
    }

    unsigned long long find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask)
    {
        size -= static_cast<unsigned long>(strlen(mask));
        for (unsigned long i = 0; i < size; i++)
        {
            if (pattern_check(reinterpret_cast<const char*>(addr) + i, pattern, mask))
                return addr + i;
        }
        return 0;
    }

    unsigned long long find_pattern_image(unsigned long long addr, const char* pattern, const char* mask)
    {
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(addr);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(addr + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        auto section = IMAGE_FIRST_SECTION(nt);
        for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            auto p = &section[i];
            if (strstr(reinterpret_cast<const char*>(p->Name), ".text") || 'EGAP' == *reinterpret_cast<int*>(p->Name))
            {
                DWORD64 res = find_pattern(addr + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
                if (res) return res;
            }
        }
        return 0;
    }

    wchar_t* random_wstring(wchar_t* str, size_t size)
    {
        if (str)
        {
            ULONG64 time = 0;
            KeQuerySystemTime(&time);
            ULONG seed = static_cast<ULONG>(time);
            static const wchar_t maps[62] = L"123456789ZXCVBNMASDFGHJKLQWERTYUIOPzxcvbnmasdfghjklqwertyuiop";

            if (size == 0) size = wcslen(str);
            for (size_t i = 0; i < size; i++) str[i] = maps[RtlRandomEx(&seed) % 60];
        }
        return str;
    }

    bool build_unicode_string_from_ansi(const char* ansi, UNICODE_STRING& unicode)
    {
        if (!ansi)
            return false;
        SIZE_T length = strlen(ansi);
        if (length == 0)
            return false;

        unicode.Buffer = static_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, (length + 1) * sizeof(WCHAR), 'nUaK'));
        if (!unicode.Buffer)
            return false;

        unicode.Length = 0;
        unicode.MaximumLength = static_cast<USHORT>((length + 1) * sizeof(WCHAR));
        for (SIZE_T i = 0; i < length; ++i)
            unicode.Buffer[i] = static_cast<WCHAR>(ansi[i]);

        unicode.Buffer[length] = L'\0';
        unicode.Length = static_cast<USHORT>(length * sizeof(WCHAR));
        return true;
    }

    void free_unicode_string(UNICODE_STRING& unicode)
    {
        if (unicode.Buffer)
        {
            ExFreePoolWithTag(unicode.Buffer, 'nUaK');
            unicode.Buffer = nullptr;
        }
        unicode.Length = 0;
        unicode.MaximumLength = 0;
    }

    bool get_module_export(ULONG64 module_base, const char* name, USHORT ordinal, bool by_ordinal, ULONG64& address)
    {
        if (!module_base)
            return false;

        auto nt = getNtHeader(reinterpret_cast<PVOID>(module_base));
        if (!nt)
            return false;

        const auto& export_dir_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (export_dir_entry.Size == 0)
            return false;

        auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(module_base + export_dir_entry.VirtualAddress);
        auto functions = reinterpret_cast<PULONG>(module_base + export_dir->AddressOfFunctions);
        auto names = reinterpret_cast<PULONG>(module_base + export_dir->AddressOfNames);
        auto ordinals = reinterpret_cast<PUSHORT>(module_base + export_dir->AddressOfNameOrdinals);

        if (by_ordinal)
        {
            USHORT ordinal_index = static_cast<USHORT>(ordinal - export_dir->Base);
            if (ordinal_index >= export_dir->NumberOfFunctions)
                return false;
            address = module_base + functions[ordinal_index];
            return true;
        }

        for (ULONG i = 0; i < export_dir->NumberOfNames; ++i)
        {
            const char* export_name = reinterpret_cast<const char*>(module_base + names[i]);
            if (_stricmp(export_name, name) == 0)
            {
                USHORT ordinal_index = ordinals[i];
                address = module_base + functions[ordinal_index];
                return true;
            }
        }
        return false;
    }
}

#pragma warning(pop)