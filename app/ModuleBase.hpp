// ModuleBase.hpp
// Descobre a base virtual (endereco kernel) de um modulo kernel carregado,
// via EnumDeviceDrivers + GetDeviceDriverBaseNameW. Requer processo Admin.
#pragma once
#include <string>
#include <cstdint>

class ModuleBase {
public:
    // Retorna a base virtual (endereco kernel) do modulo cujo basename bate
    // com 'name' (case-insensitive, ex.: L"win32kbase.sys"). Lanca
    // std::runtime_error se nao encontrado ou sem privilegio.
    static uint64_t find(const std::wstring& name);
};
