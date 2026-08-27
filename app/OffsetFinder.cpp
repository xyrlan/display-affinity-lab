// OffsetFinder.cpp
#include "OffsetFinder.hpp"
#include "DriverComm.hpp"
#include <vector>
#include <stdexcept>
#include <string>
#include <cstdio>

// Constantes de DisplayAffinity (winuser.h): valores gravados na tagWND.
#ifndef WDA_NONE
#define WDA_NONE             0x00
#endif
#ifndef WDA_MONITOR
#define WDA_MONITOR          0x01
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x11
#endif

// SetWindowDisplayAffinity retorna imediato mas o efeito na tagWND pode nao
// estar aplicado ate a proxima passagem por win32k (que geralmente depende de
// mensagens serem processadas). settle() pumpa a fila e espera um pouco.
static void settle(HWND hwnd, int totalMs = 500) {
    const int step = 25;
    for (int t = 0; t < totalMs; t += step) {
        MSG msg;
        while (PeekMessageW(&msg, hwnd, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(step);
    }
}

static std::vector<uint8_t> snapshot(DriverComm& comm, HWND hwnd,
                                     DWORD mode, uint32_t rangeBytes) {
    SetWindowDisplayAffinity(hwnd, mode);
    settle(hwnd);
    return comm.readRange(hwnd, rangeBytes);
}

static void printDiffs(const char* label,
                       const std::vector<uint8_t>& a,
                       const std::vector<uint8_t>& b,
                       size_t maxShown = 12) {
    const size_t n = (a.size() < b.size()) ? a.size() : b.size();
    size_t total = 0;
    for (size_t i = 0; i < n; ++i) if (a[i] != b[i]) ++total;
    printf("[find] %s: %zu bytes diferentes\n", label, total);
    size_t shown = 0;
    for (size_t i = 0; i < n && shown < maxShown; ++i) {
        if (a[i] != b[i]) {
            printf("  +0x%04zX: 0x%02X -> 0x%02X (xor 0x%02X)\n",
                   i, a[i], b[i], (uint8_t)(a[i] ^ b[i]));
            ++shown;
        }
    }
    if (total > maxShown) printf("  ...+%zu diffs adicionais\n", total - maxShown);
}

// Escolhe UM offset+mask entre os candidatos, priorizando o par (base,target).
// candidates: offsets onde base != target. Retorna {UINT32_MAX,0} se nada estavel.
static OffsetFinder::Result pickStable(const std::vector<uint8_t>& base,
                                       const std::vector<uint8_t>& target,
                                       const std::vector<uint32_t>& candidates) {
    if (candidates.size() == 1) {
        uint32_t o = candidates[0];
        return { o, static_cast<uint8_t>(base[o] ^ target[o]) };
    }
    return { UINT32_MAX, 0 };
}

OffsetFinder::Result OffsetFinder::findOffset(DriverComm& comm, HWND hwnd,
                                              uint32_t rangeBytes) {
    if (rangeBytes == 0) {
        throw std::invalid_argument("findOffset: rangeBytes == 0");
    }

    // Snapshots dos 3 estados, com settle entre cada.
    auto sNone = snapshot(comm, hwnd, WDA_NONE,               rangeBytes);
    auto sMon  = snapshot(comm, hwnd, WDA_MONITOR,            rangeBytes);
    auto sExcl = snapshot(comm, hwnd, WDA_EXCLUDEFROMCAPTURE, rangeBytes);
    SetWindowDisplayAffinity(hwnd, WDA_NONE);
    settle(hwnd);

    const size_t n = sNone.size();
    printf("[find] tagWND primeiros 32 bytes (WDA_NONE):\n  ");
    for (size_t i = 0; i < 32 && i < n; ++i) printf("%02X ", sNone[i]);
    printf("\n");

    // Todas comparacoes que nos interessam.
    printDiffs("NONE vs MONITOR", sNone, sMon);
    printDiffs("NONE vs EXCLUDE", sNone, sExcl);
    printDiffs("MONITOR vs EXCLUDE", sMon, sExcl);

    // Filtros por valor exato, avaliados INDEPENDENTEMENTE (nao exige match
    // simultaneo em MONITOR e EXCLUDE — assim expomos o caso "so um responde").
    auto scanExact = [&](const std::vector<uint8_t>& target, uint8_t expected,
                         const char* label) {
        std::vector<uint32_t> hits;
        for (size_t i = 0; i < n && i < target.size(); ++i) {
            if (sNone[i] == 0x00 && target[i] == expected) {
                hits.push_back(static_cast<uint32_t>(i));
            }
        }
        printf("[find] %s: %zu candidato(s) exato(s)\n", label, hits.size());
        for (size_t i = 0; i < hits.size() && i < 16; ++i) {
            printf("  +0x%04X\n", hits[i]);
        }
        return hits;
    };
    auto hits01 = scanExact(sMon,  0x01, "MON  base=00 target=0x01");
    auto hits11 = scanExact(sExcl, 0x11, "EXCL base=00 target=0x11");

    // Scan "0-para-qualquer": qualquer byte que era 0x00 e virou nao-zero em EXCLUDE.
    std::vector<uint32_t> anyRise;
    for (size_t i = 0; i < n && i < sExcl.size(); ++i) {
        if (sNone[i] == 0x00 && sExcl[i] != 0x00) anyRise.push_back((uint32_t)i);
    }
    printf("[find] EXCLUDE: %zu bytes que eram 0x00 e viraram algo\n", anyRise.size());
    for (size_t i = 0; i < anyRise.size() && i < 16; ++i) {
        uint32_t o = anyRise[i];
        printf("  +0x%04X: 0x00 -> 0x%02X\n", o, sExcl[o]);
    }

    // Se o filtro exato encontrou UM unico offset em MON ou em EXCL, retornamos
    // ja aqui — respeitando a heuristica clasica pura.
    if (hits01.size() == 1) {
        printf("[find] usando filtro exato MONITOR: offset=%u mask=0xFF\n", hits01[0]);
        return { hits01[0], 0xFF };
    }
    if (hits11.size() == 1) {
        printf("[find] usando filtro exato EXCLUDE: offset=%u mask=0xFF\n", hits11[0]);
        return { hits11[0], 0xFF };
    }

    // --- CONTROLE ---
    // Se nem MONITOR nem EXCLUDE moveram bytes, precisamos saber se a leitura
    // esta VIVA. Toggle WS_EX_LAYERED (que sabidamente vive na tagWND) e
    // observa se aparece diff. Se aparecer -> confirma que WDA moveu para fora
    // da tagWND. Se nao aparecer -> ponteiro que ValidateHwnd retorna nao e
    // a tagWND "canonica" para writes.
    LONG_PTR origEx = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    SetWindowLongPtrW(hwnd, GWL_EXSTYLE, origEx | WS_EX_LAYERED);
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                 SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_FRAMECHANGED);
    settle(hwnd);
    auto sLayered = comm.readRange(hwnd, rangeBytes);
    SetWindowLongPtrW(hwnd, GWL_EXSTYLE, origEx);
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                 SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_FRAMECHANGED);
    settle(hwnd);
    printDiffs("CTRL: NONE vs +WS_EX_LAYERED", sNone, sLayered);

    // Estrategia de escolha:
    //   1) Clasico: offset onde NONE=0x00, EXCLUDE=0x11 e MONITOR=0x01 -> mask 0xFF.
    //   2) Bit-flag: unico byte que difere entre NONE e EXCLUDE -> mask=xor.
    //   3) Somente MONITOR responde (WDA_EXCLUDE foi para o DWM): unico byte
    //      que difere entre NONE e MONITOR -> util pra provar a mecanica, mas
    //      NAO removera capture-exclusion. Sinaliza claramente.
    std::vector<uint32_t> classic;
    for (size_t i = 0; i < n; ++i) {
        if (i < sMon.size() && i < sExcl.size() &&
            sNone[i] == 0x00 && sExcl[i] == 0x11 && sMon[i] == 0x01) {
            classic.push_back(static_cast<uint32_t>(i));
        }
    }
    if (classic.size() == 1) {
        printf("[find] estrategia CLASSICA: offset=%u (byte inteiro).\n", classic[0]);
        return { classic[0], 0xFF };
    }

    std::vector<uint32_t> diffExcl;
    for (size_t i = 0; i < n && i < sExcl.size(); ++i)
        if (sNone[i] != sExcl[i]) diffExcl.push_back(static_cast<uint32_t>(i));
    auto pick = pickStable(sNone, sExcl, diffExcl);
    if (pick.offset != UINT32_MAX) {
        printf("[find] estrategia BIT-FLAG (EXCLUDE): offset=%u mask=0x%02X.\n",
               pick.offset, pick.clearMask);
        return pick;
    }

    std::vector<uint32_t> diffMon;
    for (size_t i = 0; i < n && i < sMon.size(); ++i)
        if (sNone[i] != sMon[i]) diffMon.push_back(static_cast<uint32_t>(i));
    auto pickM = pickStable(sNone, sMon, diffMon);
    if (pickM.offset != UINT32_MAX) {
        printf("[find] AVISO: EXCLUDE nao mexeu na tagWND (provavel gestao pelo DWM).\n");
        printf("[find] estrategia BIT-FLAG (MONITOR): offset=%u mask=0x%02X.\n",
               pickM.offset, pickM.clearMask);
        printf("[find] limpar essa flag NAO removera WDA_EXCLUDEFROMCAPTURE nesta build.\n");
        return pickM;
    }

    throw std::runtime_error(
        "findOffset: nenhum candidato viavel em nenhum par — codificacao movida (ver diffs acima)");
}
