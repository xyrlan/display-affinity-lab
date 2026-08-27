// OffsetCache.hpp
// Persistencia do offset da flag DisplayAffinity no Registry, sob a chave de
// Parametros do proprio driver:
//   HKLM\SYSTEM\CurrentControlSet\Services\AffCtl\Parameters
//     Offset    : REG_DWORD
//     ClearMask : REG_DWORD
//
// Fluxo:
//   1. Debug: affapp faz discovery (OffsetFinder), grava aqui com save().
//   2. Release: o driver le esses valores diretamente no DriverEntry
//      (LoadPersistedOffset) — o app pode pular o discovery inteiramente.
//      Como redundancia defensiva, load() confirma que ha valor persistido
//      antes de tentar rodar o pipeline sem discovery.
//
// Requer que o processo esteja rodando com privilegio de escrita em HKLM
// (elevated / SYSTEM). Como o mesmo processo precisa abrir \\.\AffCtl (SDDL
// restrito a Admin+SYSTEM), essa premissa ja e satisfeita.
#pragma once
#include <cstdint>
#include <optional>

struct OffsetCacheEntry {
    uint32_t offset;    // byte-offset dentro da tagWND
    uint8_t  clearMask; // bits que representam a afinidade dentro do byte
};

namespace OffsetCache {

// Le do Registry. Retorna std::nullopt se ausente/ilegivel.
std::optional<OffsetCacheEntry> load();

// Grava no Registry. Retorna true se OK. Falha comum: sem privilegio.
bool save(const OffsetCacheEntry& entry);

} // namespace OffsetCache
