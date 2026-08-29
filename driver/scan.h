// scan.h
// Scan de memoria de outro processo por padrao, bypassing OpenProcess/ObCallbacks.
// Mesmo padrao do rpm.cpp: PsLookupProcessByProcessId + KeStackAttachProcess +
// leitura direta com SEH.
#pragma once
#include <ntddk.h>
#include "../shared/affctl_shared.h"

namespace affctl {

// Escaneia [startVa, startVa+size) no espaco de `pid` procurando `pattern`
// (com mascara wildcard). Preenche `out` com os hits (limitado a MaxHits).
//   out->HitCount   = quantos hits em Hits[]
//   out->Truncated  = 1 se MaxHits atingido antes do fim do range
//   out->NextVa     = VA a partir do qual continuar (0 = terminou range inteiro)
//
// Advance sempre por 1 pagina (MmIsAddressValid e O(1) — nao vale o risco de
// false-negative com skip adaptativo maior). Cost: 256MB scan varre 65536
// paginas com so MmIsAddressValid nas invalidas = < 1ms de overhead.
//
// Cancellation: cada 64 paginas checa Irp->Cancel; se setado, retorna
// STATUS_CANCELLED. Permite que affapp Ctrl+C ou driver unload cancelem
// scans longos sem trava.
//
// Assume PASSIVE_LEVEL.
NTSTATUS ScanMemoryKernel(
    PIRP irp,            // pra checar Irp->Cancel (pode ser NULL pra scan direto)
    HANDLE pid,
    ULONG_PTR startVa,
    ULONG_PTR size,
    const UCHAR* pattern,
    const UCHAR* mask,
    ULONG patternLen,
    ULONG maxHits,
    PSCAN_MEMORY_OUTPUT out);

} // namespace affctl
