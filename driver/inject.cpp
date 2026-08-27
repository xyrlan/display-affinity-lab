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

// Estende KAPC com metadados de ownership. `apc` precisa ser o PRIMEIRO membro
// — o kernel opera sobre o ponteiro dele (PKAPC), e recuperamos o AffctlApc
// via CONTAINING_RECORD dentro das rotinas.
//
// ownerProc / ownedBuffer:
//   - Se non-null, esta APC e dona do `ownedBuffer` (alocado com
//     ZwAllocateVirtualMemory no VA space de `ownerProc`). Na rundown routine,
//     fazemos attach ao processo e ZwFreeVirtualMemory para nao deixar a VA
//     do alvo com um buffer orfao caso a thread morra antes da APC disparar.
//   - Se null, o buffer e compartilhado com outras APCs (path watched — mesmo
//     buffer serve varias threads do mesmo processo). Nao liberamos aqui;
//     a VA some naturalmente com o processo alvo.
struct AffctlApc {
    KAPC      apc;
    PEPROCESS ownerProc;
    PVOID     ownedBuffer;
};

// Rotina kernel-mode: chamada ANTES da rotina normal (LoadLibraryW), no
// contexto do processo alvo. A APC vai disparar normalmente — LoadLibraryW le
// o buffer em seguida — entao NAO liberamos ownedBuffer aqui (ele fica na VA
// do processo alvo ate a morte natural do processo).
VOID InjectApcKernelRoutine(
    PKAPC Apc,
    PKNORMAL_ROUTINE* /*NormalRoutine*/,
    PVOID* /*NormalContext*/,
    PVOID* /*SystemArgument1*/,
    PVOID* /*SystemArgument2*/)
{
    if (Apc == nullptr) return;
    auto* aa = CONTAINING_RECORD(Apc, AffctlApc, apc);
    if (aa->ownerProc) {
        ObDereferenceObject(aa->ownerProc);
    }
    ExFreePoolWithTag(aa, AFFCTL_APC_TAG);
}

// Rotina de rundown: chamada se a thread alvo morrer antes da APC disparar.
// LoadLibraryW nao rodou — se somos donos do buffer, tentamos liberar dentro
// da VA do processo alvo antes de largar a referencia. Se o processo alvo
// tambem estiver terminando (comum quando a thread do EntryPoint morre com
// o processo), attach/free podem falhar — o __try/__except cobre esse caso
// e o buffer some com a VA do processo de qualquer forma.
VOID InjectApcRundownRoutine(PKAPC Apc)
{
    if (Apc == nullptr) return;
    auto* aa = CONTAINING_RECORD(Apc, AffctlApc, apc);
    if (aa->ownerProc && aa->ownedBuffer) {
        __try {
            KAPC_STATE apcState;
            KeStackAttachProcess(aa->ownerProc, &apcState);
            SIZE_T zero = 0;
            ZwFreeVirtualMemory(
                ZwCurrentProcess(), &aa->ownedBuffer, &zero, MEM_RELEASE);
            KeUnstackDetachProcess(&apcState);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Processo alvo provavelmente esta terminando — VA sera descartada.
        }
    }
    if (aa->ownerProc) {
        ObDereferenceObject(aa->ownerProc);
    }
    ExFreePoolWithTag(aa, AFFCTL_APC_TAG);
}

} // namespace

namespace affctl {

NTSTATUS AllocRemotePathBuffer(
    PEPROCESS process, PCWSTR dllPath, SIZE_T dllPathBytes, PVOID* outRemoteBuf)
{
    if (!process || !dllPath || dllPathBytes == 0 || !outRemoteBuf) {
        return STATUS_INVALID_PARAMETER;
    }
    *outRemoteBuf = nullptr;

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    PVOID  buf  = nullptr;
    SIZE_T size = dllPathBytes + sizeof(WCHAR);
    NTSTATUS status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(), &buf, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (NT_SUCCESS(status)) {
        __try {
            RtlCopyMemory(buf, dllPath, dllPathBytes);
            ((PWCHAR)buf)[dllPathBytes / sizeof(WCHAR)] = L'\0';
            *outRemoteBuf = buf;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SIZE_T freeSize = 0;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &buf, &freeSize, MEM_RELEASE);
            status = STATUS_ACCESS_VIOLATION;
        }
    }

    KeUnstackDetachProcess(&apcState);
    return status;
}

NTSTATUS QueueLoadLibraryApc(
    PETHREAD  thread,
    PVOID     loadLibraryAddr,
    PVOID     remotePathBuf,
    PEPROCESS ownerProcess)
{
    if (!thread || !loadLibraryAddr || !remotePathBuf) {
        return STATUS_INVALID_PARAMETER;
    }
    auto* aa = (AffctlApc*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AffctlApc), AFFCTL_APC_TAG);
    if (!aa) return STATUS_INSUFFICIENT_RESOURCES;

    // Ownership do buffer: se caller passou ownerProcess, referenciamos aqui
    // pra manter EPROCESS vivo caso a rundown precise fazer attach depois.
    // A referencia e devolvida em InjectApcKernelRoutine ou InjectApcRundownRoutine.
    if (ownerProcess) {
        ObReferenceObject(ownerProcess);
        aa->ownerProc   = ownerProcess;
        aa->ownedBuffer = remotePathBuf;
    } else {
        aa->ownerProc   = nullptr;
        aa->ownedBuffer = nullptr; // buffer compartilhado — nao libera aqui
    }

    KeInitializeApc(
        &aa->apc,
        (PRKTHREAD)thread,
        OriginalApcEnvironment,
        InjectApcKernelRoutine,
        InjectApcRundownRoutine,
        (PKNORMAL_ROUTINE)loadLibraryAddr,
        UserMode,
        remotePathBuf);

    BOOLEAN inserted = KeInsertQueueApc(&aa->apc, nullptr, nullptr, IO_NO_INCREMENT);
    if (!inserted) {
        // Nenhuma rotina vai rodar — desfazemos ownership manualmente.
        if (aa->ownerProc) {
            ObDereferenceObject(aa->ownerProc);
        }
        ExFreePoolWithTag(aa, AFFCTL_APC_TAG);
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

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

    // 1) Aloca + copia o path no espaco do alvo.
    PVOID remoteBuf = nullptr;
    status = AllocRemotePathBuffer(targetProc, dllPath, dllPathBytes, &remoteBuf);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(targetThread);
        ObDereferenceObject(targetProc);
        return status;
    }

    // 2) Enfileira APC user-mode com LoadLibraryW. Passamos targetProc como
    //    owner do buffer — a rundown routine libera o buffer se a thread morrer
    //    antes da APC disparar (ela referencia targetProc internamente, alem
    //    da referencia local que soltamos abaixo).
    status = QueueLoadLibraryApc(targetThread, loadLibraryAddr, remoteBuf, targetProc);
    // Se KeInsertQueueApc falhou dentro de QueueLoadLibraryApc, a APC nao vai
    // rodar — nem a rundown. O buffer remoto vira leak minusculo (< 1KB) na
    // VA do processo alvo, que some quando ele morrer. Aceitavel.

    ObDereferenceObject(targetThread);
    ObDereferenceObject(targetProc);
    return status;
}

} // namespace affctl
