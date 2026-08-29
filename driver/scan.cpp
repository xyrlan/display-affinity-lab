// scan.cpp
// Kernel-side memory scan with masked pattern match.
//
// Algoritmo:
//   1. attach ao processo alvo (uma vez pra todo scan)
//   2. loop por pagina em [startVa, startVa+size)
//   3. pra cada pagina:
//      - MmIsAddressValid(pageStart) → se invalida, skip adaptativo (64K→1M→64M)
//      - se valida: memcmp masked pelo range util da pagina (ate PatternLen do fim)
//      - hits sao appended em out->Hits[] ate MaxHits
//   4. se MaxHits atingido: Truncated=1, NextVa=proxima posicao apos ultimo hit
//   5. se acabou range inteiro: NextVa=0
//
// Cuidado com boundaries:
//   - Padrao pode cruzar page boundary. Estratégia: pra cada pagina val, valida
//     tambem a pagina seguinte (pra pattern que ultrapassa). Se seguinte invalida,
//     limita busca a (pageEnd - patternLen + 1) offsets dentro desta pagina.
//   - SEH cobre races (pagina paged out entre valid check e memcmp).
//
// Perf note: sem SIMD, sem Boyer-Moore. Pra padroes curtos (typical: 4 bytes de
// int32) memcmp e trivial. Se algum dia precisarmos scan de padroes longos em
// GBs, otimizar. Por ora, prioriza clareza.
#include <ntifs.h>
#include "scan.h"

// ZwQueryVirtualMemory ja e declarada em ntifs.h (WDK 26100). Usando
// ZwCurrentProcess() (pseudo -1) apos KeStackAttachProcess opera no
// processo attached, sem passar por ObpCreateHandle -- pseudo -1 e resolvido
// pra PsGetCurrentProcess. Nao dispara ObCallbacks do EMAC.

namespace affctl {

namespace {

constexpr ULONG_PTR kPage        = 0x1000;     // 4KB
constexpr ULONG      kCancelCheckPeriod = 64;  // check Irp->Cancel a cada N paginas

// Retorna true se `buf[i]` casa com `pattern[i]` para todo i com mask[i]==0xFF.
// mask[i]==0x00 = wildcard (aceita qualquer byte). mask[i] intermediario nao e
// suportado (usado como boolean 0xFF ou 0x00).
static inline bool MatchAt(const UCHAR* buf, const UCHAR* pattern, const UCHAR* mask, ULONG len) {
    for (ULONG i = 0; i < len; ++i) {
        if (mask[i] && buf[i] != pattern[i]) return false;
    }
    return true;
}

} // namespace

NTSTATUS ScanMemoryKernel(
    PIRP irp,
    HANDLE pid,
    ULONG_PTR startVa,
    ULONG_PTR size,
    const UCHAR* pattern,
    const UCHAR* mask,
    ULONG patternLen,
    ULONG maxHits,
    PSCAN_MEMORY_OUTPUT out)
{
    if (pid == nullptr || pattern == nullptr || mask == nullptr || out == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    if (patternLen == 0 || patternLen > AFFCTL_SCAN_MAX_PATTERN) {
        return STATUS_INVALID_PARAMETER;
    }
    if (maxHits == 0 || maxHits > AFFCTL_SCAN_MAX_HITS) {
        return STATUS_INVALID_PARAMETER;
    }
    if (size == 0 || size > AFFCTL_SCAN_MAX_CHUNK) {
        return STATUS_INVALID_PARAMETER;
    }
    // Overflow + limite user space (0x7FFFFFFFFFFF).
    if (startVa + size < startVa) return STATUS_INVALID_PARAMETER;
    if (startVa + size > 0x7FFFFFFFFFFFULL) return STATUS_INVALID_PARAMETER;

    // Zerar output (importante: caller confia nos valores).
    out->HitCount = 0;
    out->Truncated = 0;
    out->NextVa = 0;

    PEPROCESS proc = nullptr;
    NTSTATUS s = PsLookupProcessByProcessId(pid, &proc);
    if (!NT_SUCCESS(s)) return STATUS_NOT_FOUND;

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    ULONG_PTR va       = startVa;
    ULONG_PTR endVa    = startVa + size;
    ULONG     pagesSinceCancelCheck = 0;

    // Alinha va no comeco da pagina — MmIsAddressValid opera por pagina.
    ULONG_PTR pageAligned = va & ~(kPage - 1);
    if (pageAligned != va) {
        // Se startVa nao esta alinhado, comeca no comeco da propria pagina;
        // matches antes de startVa sao filtrados abaixo.
        va = pageAligned;
    }

    while (va < endVa) {
        // Cancellation check periodico — permite Ctrl+C do affapp / driver unload
        // interromperem scans longos sem trava.
        if (++pagesSinceCancelCheck >= kCancelCheckPeriod) {
            pagesSinceCancelCheck = 0;
            if (irp != nullptr && irp->Cancel) {
                out->NextVa = va; // caller pode retomar dali se quiser
                s = STATUS_CANCELLED;
                goto done;
            }
        }

        // MmIsAddressValid: checa se pagina esta no working set (nao paged out
        // nem unmapped). Nao segura o mapping, mas serve como filtro rapido.
        bool valid = MmIsAddressValid((PVOID)va) != FALSE;
        if (!valid) {
            // Consulta a VAD via ZwQueryVirtualMemory pra saber o fim desta
            // regiao (unmapped/reserved/no-access) e pular ATE LA — nao alem.
            // Isso e safe (nao ha memoria commit no meio, por definicao do VAD)
            // e essencial pra performance em x64 (128TB user space com poucos
            // GBs de allocs seria intratavel de outra forma).
            //
            // ZwCurrentProcess() apos KeStackAttachProcess opera no processo
            // attached (pseudo -1 -> PsGetCurrentProcess). Nao passa por
            // ObpCreateHandle -> nao dispara ObCallbacks do EMAC.
            //
            // Se query falhar, fallback conservador: avanca 1 pagina.
            MEMORY_BASIC_INFORMATION mbi{};
            SIZE_T retLen = 0;
            NTSTATUS qs = ZwQueryVirtualMemory(
                ZwCurrentProcess(), (PVOID)va,
                (MEMORY_INFORMATION_CLASS)0 /*MemoryBasicInformation*/,
                &mbi, sizeof(mbi), &retLen);
            if (NT_SUCCESS(qs) && mbi.RegionSize > 0) {
                // Se State=MEM_COMMIT e apenas paged out, avanca 1 pagina (talvez
                // proxima esteja carregada). Se State != MEM_COMMIT (FREE ou
                // RESERVE) ou Protect=PAGE_NOACCESS, pula regiao inteira.
                ULONG_PTR regionEnd = (ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize;
                if (mbi.State != MEM_COMMIT ||
                    (mbi.Protect & PAGE_NOACCESS) ||
                    (mbi.Protect == 0)) {
                    // Regiao inteira sem memoria acessivel — pula
                    va = regionEnd;
                    if (va <= (ULONG_PTR)mbi.BaseAddress) va = (ULONG_PTR)mbi.BaseAddress + kPage; // sanity
                    continue;
                }
            }
            // Fallback: pagina paged out ou query falhou. Avanca 1 pagina.
            va += kPage;
            continue;
        }

        // Determina range util dentro desta pagina.
        // Pattern pode cruzar pra pagina seguinte — checa se ela e valida.
        ULONG_PTR pageEnd = va + kPage;
        ULONG_PTR searchEnd;
        bool nextPageValid = (va + kPage < endVa) && (MmIsAddressValid((PVOID)(va + kPage)) != FALSE);
        if (nextPageValid) {
            // Pattern pode cruzar pra pagina seguinte com seguranca — busca ate pageEnd.
            searchEnd = pageEnd;
        } else {
            // Limita busca pra nao ler alem da pagina.
            searchEnd = pageEnd - patternLen + 1;
            if (searchEnd <= va) {
                // patternLen > PAGE_SIZE — muito grande, skip pagina
                va = pageEnd;
                continue;
            }
        }
        if (searchEnd > endVa) searchEnd = endVa;

        // Busca sequencial no range util. Cada offset e um candidate; MatchAt
        // le patternLen bytes a partir dele.
        for (ULONG_PTR p = va; p < searchEnd; ++p) {
            // Skip candidates antes do startVa original (caso de re-alignment).
            if (p < startVa) continue;

            __try {
                if (MatchAt((const UCHAR*)p, pattern, mask, patternLen)) {
                    if (out->HitCount >= maxHits) {
                        // Truncou — retorna cursor
                        out->Truncated = 1;
                        out->NextVa = p; // proxima chamada retoma AQUI (inclusive)
                        goto done;
                    }
                    out->Hits[out->HitCount++] = (unsigned long long)p;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Pagina foi paged out entre valid check e memcmp — pula resto da pagina.
                break;
            }
        }

        va = pageEnd;
    }

    // Terminou o range inteiro sem truncar.
    out->NextVa = 0;

done:
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    return s;
}

} // namespace affctl
