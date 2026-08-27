// PdbResolver.cpp
#include "PdbResolver.hpp"
#include <windows.h>
#include <dbghelp.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstring>

#pragma comment(lib, "dbghelp.lib")

namespace {

std::string toNarrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        s.data(), n, nullptr, nullptr);
    return s;
}

// Configura _NT_SYMBOL_PATH para SymSrv apontando o cache em %TEMP%\SymCache.
void ensureSymbolPath() {
    wchar_t tempPath[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, tempPath);
    if (n == 0 || n > MAX_PATH) {
        throw std::runtime_error("GetTempPathW falhou");
    }
    std::wstring cache = std::wstring(tempPath) + L"SymCache";
    CreateDirectoryW(cache.c_str(), nullptr); // ok se ja existe

    // srv*<cache>*https://msdl.microsoft.com/download/symbols
    std::wstring symPath = L"srv*" + cache + L"*https://msdl.microsoft.com/download/symbols";
    // Nao sobrescreve se o usuario ja definiu _NT_SYMBOL_PATH.
    wchar_t existing[8];
    DWORD ex = GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", existing, 8);
    if (ex == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
        SetEnvironmentVariableW(L"_NT_SYMBOL_PATH", symPath.c_str());
    }
}

} // namespace

PdbResolver::PdbResolver(const std::wstring& modulePath)
    : m_modulePath(modulePath) {

    ensureSymbolPath();

    // Pseudo-handle: usamos GetCurrentProcess (padrao dbghelp).
    m_hProcess = GetCurrentProcess();

    // Ativa auto-load de simbolos via SymSrv + traces em debug se quiser.
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES |
                  SYMOPT_UNDNAME | SYMOPT_AUTO_PUBLICS);

    if (!SymInitializeW(m_hProcess, nullptr, FALSE)) {
        DWORD e = GetLastError();
        m_hProcess = nullptr;
        throw std::runtime_error("SymInitializeW falhou (code=" +
                                 std::to_string(e) + ")");
    }

    // Base ficticia = 0x10000000 (arbitrario; dbghelp so precisa que seja !=0
    // e nao colidir com outro modulo carregado).
    const DWORD64 fakeBase = 0x0000000010000000ULL;

    DWORD64 loaded = SymLoadModuleExW(
        m_hProcess,
        nullptr,
        m_modulePath.c_str(),
        nullptr,
        fakeBase,
        0,        // DllSize (0 = deduz do arquivo)
        nullptr,
        0);

    if (loaded == 0) {
        DWORD e = GetLastError();
        SymCleanup(m_hProcess);
        m_hProcess = nullptr;
        throw std::runtime_error("SymLoadModuleExW falhou p/ '" +
                                 toNarrow(m_modulePath) + "' (code=" +
                                 std::to_string(e) +
                                 "). PDB nao baixou? Sem internet no 1o run?");
    }
    m_moduleBase = loaded;
}

PdbResolver::~PdbResolver() {
    if (m_hProcess != nullptr) {
        SymUnloadModule64(m_hProcess, m_moduleBase);
        SymCleanup(m_hProcess);
        m_hProcess = nullptr;
    }
}

// Callback do SymEnumSymbols
static BOOL CALLBACK enumCb(PSYMBOL_INFO info, ULONG /*size*/, PVOID ctx) {
    auto* out = reinterpret_cast<std::vector<PdbResolver::SymHit>*>(ctx);
    PdbResolver::SymHit h;
    h.name = std::string(info->Name, info->NameLen);
    // Address vem em endereco absoluto (base ficticia + rva). Base = 0x10000000.
    h.rva  = static_cast<uint32_t>(info->Address - 0x10000000ULL);
    h.size = info->Size;
    out->push_back(std::move(h));
    return TRUE; // continua
}

std::vector<PdbResolver::SymHit> PdbResolver::enumSymbols(const char* mask) const {
    std::vector<SymHit> out;
    SymEnumSymbols(m_hProcess, m_moduleBase, mask, enumCb, &out);
    return out;
}

uint32_t PdbResolver::rvaOf(const char* symbol) const {
    // SYMBOL_INFO + buffer p/ nome.
    constexpr size_t kMaxName = 256;
    std::vector<uint8_t> buf(sizeof(SYMBOL_INFO) + kMaxName);
    auto info = reinterpret_cast<PSYMBOL_INFO>(buf.data());
    info->SizeOfStruct = sizeof(SYMBOL_INFO);
    info->MaxNameLen = static_cast<ULONG>(kMaxName);

    if (!SymFromName(m_hProcess, symbol, info)) {
        DWORD e = GetLastError();
        throw std::runtime_error(std::string("SymFromName('") + symbol +
                                 "') falhou (code=" + std::to_string(e) +
                                 "). Simbolo publicado no PDB?");
    }
    // RVA = Address absoluto - base ficticia
    uint64_t rva = info->Address - m_moduleBase;
    if (rva > 0xFFFFFFFFULL) {
        throw std::runtime_error(std::string("RVA fora de 32 bits para '") + symbol + "'");
    }
    return static_cast<uint32_t>(rva);
}
