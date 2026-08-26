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
    // Descobre o offset usando 'win' (janela propria) e o driver 'comm'.
    // Retorna o offset em bytes. Lanca std::runtime_error se 0 ou >1 candidato
    // sobreviverem a desambiguacao. Restaura WDA_NONE ao final.
    // 'rangeBytes' = quantos bytes da tagWND varrer (default 512).
    static uint32_t findOffset(DriverComm& comm, HWND hwnd,
                               uint32_t rangeBytes = 512);
};
