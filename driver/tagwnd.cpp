// tagwnd.cpp
// Implementacao da resolucao HWND->tagWND e acesso guardado por SEH.
#include "tagwnd.h"
#include "win32k_structs.h"
#include "../shared/affctl_shared.h"

namespace {

// Ponteiro cacheado para gSharedInfo (localizado uma vez por InitSharedInfo).
PSHAREDINFO g_pSharedInfo = nullptr;

// Numero maximo de entradas que aceitamos indexar em aheList. Guarda defensiva
// contra HWND com indice absurdo antes de confiar no array.
constexpr unsigned long kMaxHandleIndex = 0x10000; // 16 bits

// ---------------------------------------------------------------------------
// FindGSharedInfo
//
// Localiza o endereco de gSharedInfo dentro de win32kbase.sys.
//
// gSharedInfo NAO e exportado, entao MmGetSystemRoutineAddress nao o encontra.
// A abordagem correta e um pattern scan (AOB) na secao de dados do modulo
// win32kbase.sys, OU derivar o endereco a partir de uma funcao exportada
// conhecida que o referencia.
//
// ESTE STUB retorna nullptr de proposito. O pattern/endereco varia por build do
// Windows e deve ser calibrado na VM alvo. Ver README secao
// "Pattern e validacao de structs" para:
//   - obter o endereco com WinDbg: `x win32kbase!gSharedInfo`
//   - montar/ajustar o pattern de bytes aqui
// Manter esta funcao isolada permite trocar so ela sem tocar no resto.
// ---------------------------------------------------------------------------
PSHAREDINFO FindGSharedInfo() {
    // TODO(calibracao-VM): preencher com pattern scan real ou endereco derivado.
    // Retornar (PSHAREDINFO)<endereco de gSharedInfo>.
    return nullptr;
}

} // namespace

namespace affctl {

NTSTATUS InitSharedInfo() {
    if (g_pSharedInfo != nullptr) {
        return STATUS_SUCCESS;
    }
    PSHAREDINFO p = FindGSharedInfo();
    if (p == nullptr) {
        return STATUS_NOT_FOUND;
    }
    g_pSharedInfo = p;
    return STATUS_SUCCESS;
}

PVOID ResolveTagWnd(ULONG_PTR hwnd) {
    if (!NT_SUCCESS(InitSharedInfo())) {
        return nullptr;
    }

    PVOID result = nullptr;

    __try {
        PSHAREDINFO psi = g_pSharedInfo;
        if (psi == nullptr || psi->aheList == nullptr) {
            return nullptr;
        }

        unsigned long index = HWND_INDEX(hwnd);
        if (index >= kMaxHandleIndex) {
            return nullptr;
        }

        PHANDLEENTRY he = &psi->aheList[index];
        if (!MmIsAddressValid(he)) {
            return nullptr;
        }

        // So janelas; e phead precisa ser valido.
        if (he->bType != TYPE_WINDOW || he->phead == nullptr) {
            return nullptr;
        }
        if (!MmIsAddressValid(he->phead)) {
            return nullptr;
        }

        result = he->phead; // inicio do objeto == base da tagWND
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = nullptr;
    }

    return result;
}

NTSTATUS ReadTagWndRange(ULONG_PTR hwnd, PVOID out, ULONG count) {
    if (out == nullptr || count == 0 || count > AFFCTL_MAX_RANGE) {
        return STATUS_INVALID_PARAMETER;
    }

    PVOID pTagWnd = ResolveTagWnd(hwnd);
    if (pTagWnd == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    __try {
        // Checagem best-effort do primeiro e ultimo byte do range.
        if (!MmIsAddressValid(pTagWnd) ||
            !MmIsAddressValid((PUCHAR)pTagWnd + count - 1)) {
            return STATUS_ACCESS_VIOLATION;
        }
        RtlCopyMemory(out, pTagWnd, count);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }
    return status;
}

NTSTATUS ReadFlag(ULONG_PTR hwnd, ULONG offset, unsigned char* value) {
    if (value == nullptr || offset >= AFFCTL_MAX_RANGE) {
        return STATUS_INVALID_PARAMETER;
    }

    PVOID pTagWnd = ResolveTagWnd(hwnd);
    if (pTagWnd == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    __try {
        PUCHAR addr = (PUCHAR)pTagWnd + offset;
        if (!MmIsAddressValid(addr)) {
            return STATUS_ACCESS_VIOLATION;
        }
        *value = *addr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }
    return status;
}

NTSTATUS ClearFlag(ULONG_PTR hwnd, ULONG offset) {
    if (offset >= AFFCTL_MAX_RANGE) {
        return STATUS_INVALID_PARAMETER;
    }

    PVOID pTagWnd = ResolveTagWnd(hwnd);
    if (pTagWnd == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    __try {
        PUCHAR addr = (PUCHAR)pTagWnd + offset;
        if (!MmIsAddressValid(addr)) {
            return STATUS_ACCESS_VIOLATION;
        }
        *addr = 0x00; // WDA_NONE
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }
    return status;
}

} // namespace affctl
