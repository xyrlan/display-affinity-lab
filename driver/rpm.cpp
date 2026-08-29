// rpm.cpp
// Implementacao do IOCTL_READ_PROCESS_MEMORY.
//
// Design:
//   - PsLookupProcessByProcessId + KeStackAttachProcess evita HANDLE ->
//     nao passa por ObRegisterCallbacks do anti-cheat.
//   - Range check por pagina antes de tocar: percorremos as paginas em [srcVa,
//     srcVa+size) e usamos MmIsAddressValid pra cada uma. Isso evita SEH em
//     paginas nao-mapeadas (mais eficiente que confiar so em __try/__except).
//   - SEH ainda envolve o memcpy final por defesa em profundidade (paginas
//     podem ser paged out entre o probe e a copia).
//   - Cross-page reads: dividimos em chunks por pagina pra que uma page fault
//     numa pagina nao anule a leitura das outras.
//
// Limitacoes conhecidas:
//   - Nao contorna PPL/protected process (o attach falharia).
//   - Nao contorna HVCI + memory encryption em enclaves (raro).
//   - Nao mata detectors que registrem PsSetProcessNotifyRoutine e chequem
//     "quem esta atacando meu processo" — mas isso e notify, nao pode BLOQUEAR
//     a leitura, so registrar depois.
#include <ntifs.h>
#include "rpm.h"
#include "../shared/affctl_shared.h"

// PsGetProcessSectionBaseAddress: export do kernel, retorna VA do PE image
// base do processo alvo (mesmo que EPROCESS->SectionBaseAddress). Nao esta
// no ntddk.h publico — declarar aqui. Nao requer attach, nao abre HANDLE.
extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTKERNELAPI PPEB  NTAPI PsGetProcessPeb(PEPROCESS Process);

namespace affctl {

namespace {

// Probe defensivo: valida cada pagina no range [va, va+size). Retorna false na
// primeira invalida. MmIsAddressValid nao e infalivel (nao segura o mapping),
// mas serve pra rejeitar rapidamente ranges obviamente invalidos antes do attach.
static bool AllPagesValidInTargetContext(ULONG_PTR va, ULONG size) {
    if (size == 0) return true;
    ULONG_PTR start = va & ~((ULONG_PTR)PAGE_SIZE - 1);
    ULONG_PTR end   = (va + size + PAGE_SIZE - 1) & ~((ULONG_PTR)PAGE_SIZE - 1);
    for (ULONG_PTR p = start; p < end; p += PAGE_SIZE) {
        if (!MmIsAddressValid((PVOID)p)) return false;
    }
    return true;
}

} // namespace

NTSTATUS ReadProcessMemoryKernel(
    HANDLE pid,
    ULONG_PTR srcVa,
    ULONG size,
    PVOID dst)
{
    if (pid == nullptr || dst == nullptr || size == 0 || size > AFFCTL_RPM_MAX) {
        return STATUS_INVALID_PARAMETER;
    }
    // Rejeita ranges kernel obvios (bit alto). Kernel space nao pertence ao alvo.
    // Range user (Win10/11 x64): 0x0000'0000'0000'0000 .. 0x0000'7FFF'FFFF'FFFF.
    if (srcVa >= 0x7FFF'FFFF'FFFFULL) {
        return STATUS_INVALID_PARAMETER;
    }
    // Overflow check.
    if (srcVa + size < srcVa) {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS proc = nullptr;
    NTSTATUS s = PsLookupProcessByProcessId(pid, &proc);
    if (!NT_SUCCESS(s)) {
        return STATUS_NOT_FOUND;
    }

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    NTSTATUS result = STATUS_SUCCESS;

    // Probe primeiro — se qualquer pagina no range esta invalida, aborta cedo
    // sem tentar memcpy que causaria fault.
    if (!AllPagesValidInTargetContext(srcVa, size)) {
        result = STATUS_ACCESS_VIOLATION;
    } else {
        __try {
            // Copy em chunks por pagina evita anular leitura toda por 1 fault
            // no meio do range. Mas na pratica, se AllPagesValid ja disse OK,
            // podemos copiar em bloco unico — o SEH cobre races.
            RtlCopyMemory(dst, (PVOID)srcVa, size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            result = STATUS_ACCESS_VIOLATION;
        }
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);

    return result;
}

NTSTATUS GetProcessImageBase(HANDLE pid, ULONG_PTR* outImageBase) {
    if (pid == nullptr || outImageBase == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    *outImageBase = 0;

    PEPROCESS proc = nullptr;
    NTSTATUS s = PsLookupProcessByProcessId(pid, &proc);
    if (!NT_SUCCESS(s)) return STATUS_NOT_FOUND;

    PVOID base = PsGetProcessSectionBaseAddress(proc);
    *outImageBase = (ULONG_PTR)base;

    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}

NTSTATUS GetProcessPeb(HANDLE pid, ULONG_PTR* outPebVa) {
    if (pid == nullptr || outPebVa == nullptr) return STATUS_INVALID_PARAMETER;
    *outPebVa = 0;
    PEPROCESS proc = nullptr;
    NTSTATUS s = PsLookupProcessByProcessId(pid, &proc);
    if (!NT_SUCCESS(s)) return STATUS_NOT_FOUND;
    // PsGetProcessPeb pode ser chamado em qualquer contexto (nao precisa attach).
    // Retorna PPEB no address space do processo alvo. Se caller estiver em outro
    // contexto (attached ou nao), o VA sozinho nao e desreferenciavel — precisa
    // KeStackAttachProcess (ou RPM subsequente) pra ler.
    PPEB peb = PsGetProcessPeb(proc);
    *outPebVa = (ULONG_PTR)peb;
    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}

} // namespace affctl
