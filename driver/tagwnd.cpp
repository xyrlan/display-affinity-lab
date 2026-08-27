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

// Ponteiro para win32kbase!ValidateHwnd, injetado do user-mode. Assinatura
// interna (nao-documentada) e estavel ha muitas versoes: PWND (NTAPI *)(HWND).
// HWND e tipo user-mode (windef.h); no kernel usamos HANDLE, layout identico.
typedef PVOID (NTAPI *PFN_VALIDATE_HWND)(HANDLE hwnd);
PFN_VALIDATE_HWND g_pValidateHwnd = nullptr;

// Numero maximo de entradas que aceitamos indexar em aheList. Guarda defensiva
// contra HWND com indice absurdo antes de confiar no array.
constexpr unsigned long kMaxHandleIndex = 0x10000; // 16 bits

} // namespace

namespace affctl {

NTSTATUS SetValidateHwndAddress(PVOID addr) {
    if (addr == nullptr || !MmIsAddressValid(addr)) {
        return STATUS_INVALID_PARAMETER;
    }
    g_pValidateHwnd = reinterpret_cast<PFN_VALIDATE_HWND>(addr);
    return STATUS_SUCCESS;
}

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
    // Caminho preferencial: chamar win32kbase!ValidateHwnd (oficial da MS).
    // Estavel em Win10 e Win11; unico caminho viavel a partir do Win11 25H2 (a
    // phead sumiu da HANDLEENTRY publica).
    if (g_pValidateHwnd != nullptr) {
        PVOID result = nullptr;
        __try {
            result = g_pValidateHwnd(reinterpret_cast<HANDLE>(hwnd));
            if (result != nullptr && !MmIsAddressValid(result)) {
                result = nullptr;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            result = nullptr;
        }
        if (result != nullptr) {
            return result;
        }
        // Fallback silencioso: assinatura pode ter mudado; tenta aheList.
    }

    // Fallback: aheList[idx].phead (funciona em Win10 e alguns Win11 antigos).
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

NTSTATUS ClearFlag(ULONG_PTR hwnd, ULONG offset, unsigned char mask) {
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
        // Preserva os outros bits do byte (bitfield em Win11 25H2+).
        *addr = static_cast<UCHAR>(*addr & ~mask);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }
    return status;
}

NTSTATUS Diag(ULONG_PTR hwnd, void* out) {
    if (out == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    PAFF_DIAG_OUTPUT d = reinterpret_cast<PAFF_DIAG_OUTPUT>(out);
    RtlZeroMemory(d, sizeof(*d));

    PUCHAR base = reinterpret_cast<PUCHAR>(g_pSharedInfo);
    d->gShared = reinterpret_cast<unsigned long long>(base);
    d->index   = HWND_INDEX(hwnd);

    unsigned long long rawPhead = 0;

    __try {
        if (base != nullptr && MmIsAddressValid(base)) {
            d->gSharedValid = 1;
            RtlCopyMemory(d->gSharedRaw, base, sizeof(d->gSharedRaw));
            d->aheListPtr  = *reinterpret_cast<unsigned long long*>(base + 0x08);
            d->heEntrySize = *reinterpret_cast<unsigned long*>(base + 0x10);
        }

        PUCHAR he = reinterpret_cast<PUCHAR>(d->aheListPtr);
        if (he != nullptr) {
            // Use o esz reportado pela SHAREDINFO; fallback = 32 (Win10/11 modernos).
            ULONG esz = d->heEntrySize ? d->heEntrySize : 32u;
            he += static_cast<ULONG_PTR>(d->index) * esz;
            d->hePtr = reinterpret_cast<unsigned long long>(he);
            if (MmIsAddressValid(reinterpret_cast<PUCHAR>(d->aheListPtr))) {
                d->aheListValid = 1;
            }
            if (MmIsAddressValid(he)) {
                d->heValid = 1;
                RtlCopyMemory(d->heRaw, he, sizeof(d->heRaw));
                // Layout Win11 25H2: bType/bFlags/wUniq em +0x18/+0x19/+0x1A.
                d->bType  = he[0x18];
                d->bFlags = he[0x19];
                d->wUniq  = *reinterpret_cast<unsigned short*>(he + 0x1A);
                rawPhead  = *reinterpret_cast<unsigned long long*>(he + 0x00);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Mantem o que ja foi preenchido; nunca causa BSOD.
    }

    // Sondagem do phead: testa varias hipoteses de decodificacao.
    // Cand 0: valor cru (caso ja seja pointer completo).
    // Cand 1..3: bits altos herdados de win32kbase / psi / aheList (caso seja offset).
    const unsigned long long HI_MASK = 0xFFFFFFFF00000000ULL;
    unsigned long long psi     = 0;
    if (d->gSharedValid) {
        __try { psi = *reinterpret_cast<unsigned long long*>(base); }
        __except (EXCEPTION_EXECUTE_HANDLER) { psi = 0; }
    }
    unsigned long long lo = rawPhead & 0x00000000FFFFFFFFULL;

    d->pheadCand[0] = rawPhead;
    d->pheadCand[1] = (d->gShared    & HI_MASK) | lo; // high de gSharedInfo (win32kbase)
    d->pheadCand[2] = (psi           & HI_MASK) | lo; // high de psi
    d->pheadCand[3] = (d->aheListPtr & HI_MASK) | lo; // high de aheList

    for (int i = 0; i < 4; ++i) {
        PUCHAR p = reinterpret_cast<PUCHAR>(d->pheadCand[i]);
        __try {
            if (p != nullptr && MmIsAddressValid(p) &&
                MmIsAddressValid(p + sizeof(d->pheadRaw[i]) - 1)) {
                d->pheadValid[i] = 1;
                RtlCopyMemory(d->pheadRaw[i], p, sizeof(d->pheadRaw[i]));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            d->pheadValid[i] = 0;
        }
    }

    return STATUS_SUCCESS;
}

} // namespace affctl
