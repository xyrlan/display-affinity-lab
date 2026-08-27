// DriverComm.hpp
// Wrapper RAII sobre o handle do device \\.\AffCtl. Metodos tipados que
// embrulham DeviceIoControl para cada IOCTL. Erros viram std::system_error.
#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>
#include "../shared/affctl_shared.h"

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

    // Envia ao driver o endereco absoluto de win32kbase!ValidateHwnd (via PDB).
    // Habilita a resolucao HWND->tagWND oficial (necessaria em Win11 25H2+).
    void setValidateHwndAddr(uint64_t addr);

    // Informa ao driver o offset da flag DisplayAffinity + a mascara dos bits
    // dessa flag no byte-alvo (0xFF = byte inteiro, para Win10).
    void setOffset(uint32_t offset, uint8_t clearMask = 0xFF);

    // Pede ao driver para zerar (WDA_NONE) a flag da janela 'hwnd'.
    void clearAffinity(HWND hwnd);

    // Le o byte atual no offset configurado (0x00 / 0x01 / 0x11).
    uint8_t readAffinity(HWND hwnd);

    // Diagnostico: despejo cru de gSharedInfo e da entrada de handle calculada.
    AFF_DIAG_OUTPUT diag(HWND hwnd);

    // Envia IOCTL_INJECT_DLL. A struct de input ja vem pronta do Injector.
    void injectDll(const INJECT_DLL_INPUT& in);

private:
    HANDLE m_handle;

    // Helper interno: chama DeviceIoControl; lanca em falha.
    void ioctl(DWORD code,
               void* in, DWORD inLen,
               void* out, DWORD outLen,
               DWORD* bytesReturned);
};
