// PdbResolver.hpp
// Resolve RVA de simbolos em um binario do sistema (ex.: win32kbase.sys) via
// dbghelp + Microsoft Symbol Server. Baixa o PDB correspondente ao GUID+Age
// embutido no binario e faz cache em %TEMP%\SymCache.
#pragma once
#include <string>
#include <cstdint>

class PdbResolver {
public:
    // Carrega simbolos de 'modulePath' (ex.: L"C:\\Windows\\System32\\win32kbase.sys").
    // Configura _NT_SYMBOL_PATH para SymSrv (Microsoft Symbol Server) e baixa/cacheia
    // o PDB. Lanca std::runtime_error em falha.
    explicit PdbResolver(const std::wstring& modulePath);
    ~PdbResolver();

    PdbResolver(const PdbResolver&) = delete;
    PdbResolver& operator=(const PdbResolver&) = delete;

    // Retorna o RVA (offset relativo a base do modulo) do simbolo pedido.
    // Lanca std::runtime_error se o simbolo nao existir no PDB.
    uint32_t rvaOf(const char* symbol) const;

private:
    void*    m_hProcess = nullptr;   // pseudo-handle para SymInitialize
    uint64_t m_moduleBase = 0;       // base "ficticia" usada por SymLoadModuleEx
    std::wstring m_modulePath;
};
