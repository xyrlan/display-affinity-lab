// OffsetFinder.hpp
// Heuristica de descoberta do offset da flag DisplayAffinity dentro da tagWND.
//
// Ideia: toggla a afinidade de uma janela propria via a API oficial e observa,
// lendo a tagWND pelo driver, qual byte mudou de 0x00 para o valor esperado.
#pragma once
#include <windows.h>
#include <cstdint>

class DriverComm;

class OffsetFinder {
public:
    struct Result {
        uint32_t offset;    // byte-offset dentro da tagWND
        uint8_t  clearMask; // bits da afinidade dentro desse byte
    };

    // Descobre offset + mascara. Duas heuristicas em ordem:
    //  1) Clasica (Win10/11 antigos): byte que vai 0x00 -> 0x11 -> 0x01
    //     entre WDA_NONE, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR. mask=0xFF.
    //  2) Bit-flag (Win11 25H2+): unico byte que difere entre os estados.
    //     mask = (mod XOR base).
    // Lanca std::runtime_error se nenhuma heuristica achar.
    static Result findOffset(DriverComm& comm, HWND hwnd,
                             uint32_t rangeBytes = 4096);
};
