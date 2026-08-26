// OffsetFinder.cpp
#include "OffsetFinder.hpp"
#include "DriverComm.hpp"
#include <vector>
#include <stdexcept>
#include <string>

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

uint32_t OffsetFinder::findOffset(DriverComm& comm, HWND hwnd,
                                  uint32_t rangeBytes) {
    if (rangeBytes == 0) {
        throw std::invalid_argument("findOffset: rangeBytes == 0");
    }

    // --- Snapshot com WDA_NONE ---
    SetWindowDisplayAffinity(hwnd, WDA_NONE);
    std::vector<uint8_t> base = comm.readRange(hwnd, rangeBytes);

    // --- Snapshot com WDA_EXCLUDEFROMCAPTURE (0x11) ---
    SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
    std::vector<uint8_t> mod = comm.readRange(hwnd, rangeBytes);

    const size_t n = (base.size() < mod.size()) ? base.size() : mod.size();

    // Candidatos: byte que era 0x00 e virou exatamente 0x11.
    std::vector<uint32_t> candidates;
    for (size_t i = 0; i < n; ++i) {
        if (base[i] == 0x00 && mod[i] == WDA_EXCLUDEFROMCAPTURE) {
            candidates.push_back(static_cast<uint32_t>(i));
        }
    }

    // Desambiguacao: se >1 candidato, toggla WDA_MONITOR (0x01) e exige que o
    // MESMO offset passe a valer 0x01. O campo de afinidade e o unico que segue
    // esse padrao exato para os tres modos.
    if (candidates.size() > 1) {
        SetWindowDisplayAffinity(hwnd, WDA_MONITOR);
        std::vector<uint8_t> mon = comm.readRange(hwnd, rangeBytes);

        std::vector<uint32_t> refined;
        for (uint32_t off : candidates) {
            if (off < mon.size() && mon[off] == WDA_MONITOR) {
                refined.push_back(off);
            }
        }
        candidates.swap(refined);
    }

    // Restaura estado neutro.
    SetWindowDisplayAffinity(hwnd, WDA_NONE);

    if (candidates.empty()) {
        throw std::runtime_error(
            "findOffset: nenhum candidato — verifique gSharedInfo/structs (README secao Pattern)");
    }
    if (candidates.size() > 1) {
        std::string msg = "findOffset: candidatos ambiguos:";
        for (uint32_t off : candidates) msg += " " + std::to_string(off);
        throw std::runtime_error(msg);
    }

    return candidates.front();
}
