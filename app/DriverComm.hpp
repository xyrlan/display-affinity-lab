// DriverComm.hpp
// Wrapper RAII sobre o handle do device \\.\AffCtl. Metodos tipados que
// embrulham DeviceIoControl para cada IOCTL. Erros viram std::system_error.
#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>

class DriverComm {
public:
    // Abre o device. Lanca std::system_error se falhar (driver nao carregado?).
    DriverComm();
    ~DriverComm();

    DriverComm(const DriverComm&) = delete;
    DriverComm& operator=(const DriverComm&) = delete;

    // Le 'count' bytes a partir do inicio da tagWND da janela 'hwnd'.
    std::vector<uint8_t> readRange(HWND hwnd, uint32_t count);

    // Envia ao driver o endereco absoluto de gSharedInfo (resolvido no user-mode
    // via base(win32kbase.sys) + RVA(PDB)).
    void setSharedInfoAddr(uint64_t addr);

    // Informa ao driver o offset da flag DisplayAffinity descoberto pela heuristica.
    void setOffset(uint32_t offset);

    // Pede ao driver para zerar (WDA_NONE) a flag da janela 'hwnd'.
    void clearAffinity(HWND hwnd);

    // Le o byte atual no offset configurado (0x00 / 0x01 / 0x11).
    uint8_t readAffinity(HWND hwnd);

private:
    HANDLE m_handle;

    // Helper interno: chama DeviceIoControl; lanca em falha.
    void ioctl(DWORD code,
               void* in, DWORD inLen,
               void* out, DWORD outLen,
               DWORD* bytesReturned);
};
