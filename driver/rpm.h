// rpm.h
// Read Process Memory kernel-side, bypassing ObRegisterCallbacks.
//
// Tecnica:
//   1. PsLookupProcessByProcessId(pid, &proc)          — sem Object Manager path
//   2. KeStackAttachProcess(proc, &apc)                — troca CR3 pra address space alvo
//   3. RtlCopyMemory(dst, (PVOID)src_va, len) sob SEH  — leitura direta
//   4. KeUnstackDetachProcess(&apc)
//   5. ObDereferenceObject(proc)
//
// Nenhuma dessas chamadas passa por ObpCreateHandle / callbacks Ob* — o anti-cheat
// que confia em ObRegisterCallbacks pra proteger memoria nao ve nada.
//
// Assume PASSIVE_LEVEL. Requer que o pool destino seja NonPaged (SystemBuffer do
// METHOD_BUFFERED e non-paged por default).
#pragma once
#include <ntddk.h>

namespace affctl {

// Le `size` bytes de `srcVa` no espaco do processo `pid` pro buffer `dst` (kernel).
// Retorna STATUS_SUCCESS ou codigo NT em falha:
//   STATUS_INVALID_PARAMETER    args invalidos (pid=0, size=0, size > AFFCTL_RPM_MAX)
//   STATUS_NOT_FOUND            PsLookupProcessByProcessId falhou (proc morreu?)
//   STATUS_ACCESS_VIOLATION     leitura tocou VA nao-mapeada no alvo (SEH)
NTSTATUS ReadProcessMemoryKernel(
    HANDLE pid,
    ULONG_PTR srcVa,
    ULONG size,
    PVOID dst);

// Retorna PE image base do processo `pid` via PsGetProcessSectionBaseAddress.
// Sem HANDLE, sem attach — nao passa por ObCallbacks. Retorna 0 em outImageBase
// se o processo nao tem section (raro) ou sumiu; NTSTATUS reflete falha maior.
NTSTATUS GetProcessImageBase(HANDLE pid, ULONG_PTR* outImageBase);

// Retorna PPEB do processo alvo (VA no espaco dele). Combinado com RPM permite
// walk de PEB->Ldr->InLoadOrderModuleList pra enumerar modulos sem HANDLE.
NTSTATUS GetProcessPeb(HANDLE pid, ULONG_PTR* outPebVa);

} // namespace affctl
