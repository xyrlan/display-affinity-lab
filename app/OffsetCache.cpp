// OffsetCache.cpp
// Uso puro do advapi32 (RegOpenKeyEx / RegQueryValueEx / RegSetValueEx).
// Chave: HKLM\SYSTEM\CurrentControlSet\Services\AffCtl\Parameters
//   Offset    : REG_DWORD
//   ClearMask : REG_DWORD
#include "OffsetCache.hpp"
#include <windows.h>

namespace {

constexpr LPCWSTR kParamsSubKey =
    L"SYSTEM\\CurrentControlSet\\Services\\AffCtl\\Parameters";
constexpr LPCWSTR kValOffset    = L"Offset";
constexpr LPCWSTR kValClearMask = L"ClearMask";

// Le um DWORD e devolve true se tipo bate e leitura foi bem sucedida.
bool queryDword(HKEY hKey, LPCWSTR name, DWORD* out) {
    DWORD type = 0;
    DWORD data = 0;
    DWORD size = sizeof(data);
    LONG r = RegQueryValueExW(
        hKey, name, nullptr, &type,
        reinterpret_cast<LPBYTE>(&data), &size);
    if (r != ERROR_SUCCESS) return false;
    if (type != REG_DWORD || size != sizeof(DWORD)) return false;
    *out = data;
    return true;
}

} // namespace

namespace OffsetCache {

std::optional<OffsetCacheEntry> load() {
    HKEY hKey = nullptr;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kParamsSubKey, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) {
        // Subkey ausente = ainda nao houve discovery persistido.
        return std::nullopt;
    }

    DWORD off = 0, mask = 0;
    bool haveOff  = queryDword(hKey, kValOffset,    &off);
    bool haveMask = queryDword(hKey, kValClearMask, &mask);
    RegCloseKey(hKey);

    if (!haveOff) return std::nullopt;

    OffsetCacheEntry e{};
    e.offset    = off;
    e.clearMask = haveMask && mask != 0 ? static_cast<uint8_t>(mask) : 0xFF;
    return e;
}

bool clear() {
    HKEY hKey = nullptr;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kParamsSubKey, 0, KEY_SET_VALUE, &hKey);
    if (r == ERROR_FILE_NOT_FOUND) {
        // Nem a subkey existe — nada a limpar, comportamento equivalente a OK.
        return true;
    }
    if (r != ERROR_SUCCESS) return false;

    LONG r1 = RegDeleteValueW(hKey, kValOffset);
    LONG r2 = RegDeleteValueW(hKey, kValClearMask);
    RegCloseKey(hKey);

    // Ambos ERROR_FILE_NOT_FOUND tambem contam como sucesso (ja estava limpo).
    bool ok1 = (r1 == ERROR_SUCCESS || r1 == ERROR_FILE_NOT_FOUND);
    bool ok2 = (r2 == ERROR_SUCCESS || r2 == ERROR_FILE_NOT_FOUND);
    return ok1 && ok2;
}

const wchar_t* registryPath() {
    return L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AffCtl\\Parameters";
}

bool save(const OffsetCacheEntry& entry) {
    HKEY hKey = nullptr;
    DWORD disposition = 0;
    // RegCreateKeyEx com KEY_WRITE — cria a subkey se ainda nao existir.
    // Servico affctl gerou a chave Parameters/... na instalacao (INF), mas se
    // for instalacao manual via sc.exe, ela pode nao existir ainda.
    LONG r = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, kParamsSubKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, &disposition);
    if (r != ERROR_SUCCESS) {
        // Tipico: rodando sem admin. Sem admin, o CreateFileW do device ja
        // teria falhado antes — mas se ainda quisermos rodar em contexto
        // reduzido, o save simplesmente nao persiste.
        return false;
    }

    DWORD off  = entry.offset;
    DWORD mask = entry.clearMask;
    LONG r1 = RegSetValueExW(
        hKey, kValOffset, 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&off),  sizeof(off));
    LONG r2 = RegSetValueExW(
        hKey, kValClearMask, 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&mask), sizeof(mask));
    RegCloseKey(hKey);

    return r1 == ERROR_SUCCESS && r2 == ERROR_SUCCESS;
}

} // namespace OffsetCache
