
#pragma once
#include "import.hpp"
#include <ntimage.h>

#pragma warning(push)
#pragma warning(disable: 4996)

namespace utils
{
    void destroyPEHeader(PVOID image_base);

    PIMAGE_NT_HEADERS getNtHeader(PVOID base);

    bool get_module_base_address(const char* name, unsigned long long& addr, unsigned long& size);

    bool pattern_check(const char* data, const char* pattern, const char* mask);

    unsigned long long find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask);

    unsigned long long find_pattern_image(unsigned long long addr, const char* pattern, const char* mask);

    wchar_t* random_wstring(wchar_t* str, size_t size);

    bool build_unicode_string_from_ansi(const char* ansi, UNICODE_STRING& unicode);

    void free_unicode_string(UNICODE_STRING& unicode);

    bool get_module_export(ULONG64 module_base, const char* name, USHORT ordinal, bool by_ordinal, ULONG64& address);
}

#pragma warning(pop)