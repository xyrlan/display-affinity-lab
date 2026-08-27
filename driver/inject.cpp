// inject.cpp
// Injecao de DLL via APC do kernel — implementacao.
//
// Fluxo (ver diagrama no header):
//   1. PsLookupProcessByProcessId / PsLookupThreadByThreadId       (refs +1)
//   2. Validar que a thread pertence ao processo alvo              (PsGetThreadProcess)
//   3. KeStackAttachProcess                                        (contexto do alvo)
//   4. ZwAllocateVirtualMemory (READWRITE) — buffer p/ path        (no espaco do alvo)
//   5. RtlCopyMemory do path                                       (SEH)
//   6. KeUnstackDetachProcess                                      (volta ao driver)
//   7. ExAllocatePool2 (NonPaged) da KAPC                          (obrigatorio p/ APC)
//   8. KeInitializeApc (UserMode, NormalRoutine = LoadLibraryW)
//   9. KeInsertQueueApc                                            (enfileira)
//  10. ObDereferenceObject nas refs                                (refs -1)
//
// Se algo falhar, cada saida limpa exatamente o que ela alocou/referenciou.
//
// Nota de headers: usamos <ntifs.h> em vez de <ntddk.h> — ntifs.h e o header
// "file-system + private" que expoe KAPC_STATE, KeStackAttachProcess/Unstack e
// Zw*VirtualMemory, que nao ficam visiveis via ntddk.h puro.
#include <ntifs.h>
#include "inject.h"

#define AFFCTL_APC_TAG 'IApc'

// KeInitializeApc/KeInsertQueueApc historicamente eram DDIs "privadas" e ainda
// nao estao declaradas em todos os headers publicos do WDK — declaramos aqui.
// PsLookupProcess*, KeStackAttachProcess e Zw*VirtualMemory ja vem do ntifs.h.
extern "C" {

typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);

typedef VOID (NTAPI *PKKERNEL_ROUTINE)(
    struct _KAPC *Apc,
    PKNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext,
    PVOID *SystemArgument1,
    PVOID *SystemArgument2);

typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(struct _KAPC *Apc);

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

NTKERNELAPI VOID NTAPI KeInitializeApc(
    PRKAPC Apc,
    PRKTHREAD Thread,
    KAPC_ENVIRONMENT Environment,
    PKKERNEL_ROUTINE KernelRoutine,
    PKRUNDOWN_ROUTINE RundownRoutine,
    PKNORMAL_ROUTINE NormalRoutine,
    KPROCESSOR_MODE ApcMode,
    PVOID NormalContext);

NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(
    PRKAPC Apc,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    KPRIORITY Increment);

} // extern "C"

namespace {

// Rotina kernel-mode: chamada ANTES da rotina normal (LoadLibraryW). Aqui
// liberamos a KAPC alocada — KeInsertQueueApc nao libera automaticamente.
VOID InjectApcKernelRoutine(
    PKAPC Apc,
    PKNORMAL_ROUTINE* /*NormalRoutine*/,
    PVOID* /*NormalContext*/,
    PVOID* /*SystemArgument1*/,
    PVOID* /*SystemArgument2*/)
{
    if (Apc != nullptr) {
        ExFreePoolWithTag(Apc, AFFCTL_APC_TAG);
    }
}

// Rotina de rundown: chamada se a thread alvo morrer antes da APC disparar.
VOID InjectApcRundownRoutine(PKAPC Apc)
{
    if (Apc != nullptr) {
        ExFreePoolWithTag(Apc, AFFCTL_APC_TAG);
    }
}

} // namespace

namespace affctl {

NTSTATUS InjectDll(
    HANDLE pid,
    HANDLE tid,
    PVOID  loadLibraryAddr,
    PCWSTR dllPath,
    SIZE_T dllPathBytes)
{
    // Validacao basica dos parametros. Rejeita cedo — antes de qualquer alloc.
    if (loadLibraryAddr == nullptr || dllPath == nullptr ||
        dllPathBytes == 0 || dllPathBytes > 32u * 1024u) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((dllPathBytes % sizeof(WCHAR)) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS targetProc  = nullptr;
    PETHREAD  targetThread = nullptr;
    NTSTATUS  status;

    status = PsLookupProcessByProcessId(pid, &targetProc);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = PsLookupThreadByThreadId(tid, &targetThread);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(targetProc);
        return status;
    }

    // A thread precisa pertencer ao processo alvo — senao a APC injetaria
    // no processo errado (potencial crash de outro processo).
    if (PsGetThreadProcess(targetThread) != targetProc) {
        ObDereferenceObject(targetThread);
        ObDereferenceObject(targetProc);
        return STATUS_INVALID_PARAMETER;
    }

    // Attach ao contexto do alvo (PASSIVE_LEVEL requerido).
    KAPC_STATE apcState;
    KeStackAttachProcess(targetProc, &apcState);

    // Aloca buffer read-write no espaco do alvo p/ o path da DLL. Precisamos
    // de espaco pro NUL terminator porque LoadLibraryW espera WCHAR-string.
    PVOID  remoteBuf  = nullptr;
    SIZE_T bufSize    = dllPathBytes + sizeof(WCHAR);
    status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(),
        &remoteBuf,
        0,
        &bufSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(targetThread);
        ObDereferenceObject(targetProc);
        return status;
    }

    // Copia o path (protegido por SEH — remoteBuf e ponteiro user-mode).
    __try {
        RtlCopyMemory(remoteBuf, dllPath, dllPathBytes);
        // NUL-terminador logo apos os bytes copiados.
        ((PWCHAR)remoteBuf)[dllPathBytes / sizeof(WCHAR)] = L'\0';
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SIZE_T freeSize = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteBuf, &freeSize, MEM_RELEASE);
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(targetThread);
        ObDereferenceObject(targetProc);
        return STATUS_ACCESS_VIOLATION;
    }

    // Sai do contexto do alvo antes de alocar/inserir a APC (evita segurar
    // attach mais do que o necessario).
    KeUnstackDetachProcess(&apcState);

    // A KAPC precisa vir de non-paged pool (a APC pode ser processada em
    // DISPATCH_LEVEL enquanto e removida da fila).
    PKAPC apc = (PKAPC)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(KAPC), AFFCTL_APC_TAG);
    if (apc == nullptr) {
        // remoteBuf fica alocado no alvo — leak minusculo (< 1KB) e aceitavel
        // para uma falha de alocacao rara. Retornamos erro claro.
        ObDereferenceObject(targetThread);
        ObDereferenceObject(targetProc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(
        apc,
        (PRKTHREAD)targetThread,
        OriginalApcEnvironment,
        InjectApcKernelRoutine,
        InjectApcRundownRoutine,
        (PKNORMAL_ROUTINE)loadLibraryAddr,
        UserMode,
        remoteBuf);

    BOOLEAN inserted = KeInsertQueueApc(apc, nullptr, nullptr, IO_NO_INCREMENT);
    if (!inserted) {
        ExFreePoolWithTag(apc, AFFCTL_APC_TAG);
        ObDereferenceObject(targetThread);
        ObDereferenceObject(targetProc);
        return STATUS_UNSUCCESSFUL;
    }

    // Sucesso: as refs sobem +1 por PsLookup*; agora liberamos. A KAPC/buffer
    // remoto sao geridos pelo kernel/rundown.
    ObDereferenceObject(targetThread);
    ObDereferenceObject(targetProc);
    return STATUS_SUCCESS;
}

} // namespace affctl
