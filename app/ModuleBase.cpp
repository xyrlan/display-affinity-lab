// ModuleBase.cpp
#include "ModuleBase.hpp"
#include <windows.h>
#include <psapi.h>
#include <stdexcept>
#include <vector>
#include <string>
#include <cwctype>

#pragma comment(lib, "psapi.lib")

namespace {

bool iequalsW(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(a[i]) != std::towlower(b[i])) return false;
    }
    return true;
}

} // namespace

uint64_t ModuleBase::find(const std::wstring& name) {
    // 1a chamada: descobre quantos drivers ha.
    DWORD needed = 0;
    if (!EnumDeviceDrivers(nullptr, 0, &needed) || needed == 0) {
        throw std::runtime_error(
            "EnumDeviceDrivers falhou (Admin? EnumDeviceDrivers exige processo elevado)");
    }
    const size_t count = needed / sizeof(LPVOID);
    std::vector<LPVOID> bases(count);

    if (!EnumDeviceDrivers(bases.data(),
                           static_cast<DWORD>(bases.size() * sizeof(LPVOID)),
                           &needed)) {
        throw std::runtime_error("EnumDeviceDrivers (2a chamada) falhou");
    }

    wchar_t nameBuf[MAX_PATH];
    for (LPVOID base : bases) {
        DWORD got = GetDeviceDriverBaseNameW(base, nameBuf, MAX_PATH);
        if (got == 0) continue;
        std::wstring current(nameBuf, got);
        if (iequalsW(current, name)) {
            return reinterpret_cast<uint64_t>(base);
        }
    }
    throw std::runtime_error("modulo kernel nao encontrado (name mismatch?)");
}
