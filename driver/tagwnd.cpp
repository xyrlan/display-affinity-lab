// tagwnd.cpp
// Implementacao da resolucao HWND->tagWND e acesso guardado por SEH.
#include "tagwnd.h"
#include "win32k_structs.h"
#include "../shared/affctl_shared.h"

namespace {

// Ponteiro para gSharedInfo, injetado do user-mode via IOCTL_SET_GSHAREDINFO_ADDR.
// O app resolve base(win32kbase.sys) + RVA(gSharedInfo do PDB) e envia o endereco
// absoluto. Substitui o antigo pattern scan (100% preciso, future-proof).
PSHAREDINFO g_pSharedInfo = nullptr;

// Numero maximo de entradas que aceitamos indexar em aheList. Guarda defensiva
// contra HWND com indice absurdo antes de confiar no array.
constexpr unsigned long kMaxHandleIndex = 0x10000; // 16 bits

} // namespace

namespace affctl {

NTSTATUS SetSharedInfoAddress(PVOID addr) {
    if (addr == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    // Pre-check best-effort. A rede real e o __try/__except nas leituras.
    if (!MmIsAddressValid(addr)) {
        return STATUS_INVALID_PARAMETER;
    }
    g_pSharedInfo = reinterpret_cast<PSHAREDINFO>(addr);
    return STATUS_SUCCESS;
}

NTSTATUS InitSharedInfo() {
    return (g_pSharedInfo != nullptr) ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
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
