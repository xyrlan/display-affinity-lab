// inject.h
// Injecao de DLL em processo user-mode via APC do kernel.
// Tecnica: KeStackAttachProcess (contexto do alvo) + ZwAllocateVirtualMemory
// (buffer p/ path da DLL no espaco do alvo) + KeInitializeApc/KeInsertQueueApc
// (enfileira APC user-mode com LoadLibraryW como rotina normal).
//
// Requisitos operacionais:
//   - IRQL = PASSIVE_LEVEL (usa ZwAllocate*, ExAllocatePool2, attach de processo)
//   - Alvo user-mode; se for GUI, APC dispara na proxima wait alertable (rapido).
#pragma once
#include <ntddk.h>

namespace affctl {

// Enfileira APC user-mode em `tid` (thread de `pid`) que executa
// loadLibraryAddr(dllPath) no contexto do alvo. Nao bloqueia — retorna quando
// a APC foi enfileirada; o LoadLibraryW roda quando a thread entra em wait
// alertable.
//
// dllPathBytes = comprimento em BYTES do path (sem NUL terminator).
// Toda desreferencia de memoria potencialmente invalida esta sob __try/__except.
NTSTATUS InjectDll(
    HANDLE pid,
    HANDLE tid,
    PVOID  loadLibraryAddr,
    PCWSTR dllPath,
    SIZE_T dllPathBytes);

// Aloca buffer no espaco de enderecos do `process` (assume-se PASSIVE_LEVEL e
// que o caller pode chamar KeStackAttachProcess). Retorna o ponteiro remoto
// (valido no contexto do alvo) em *outRemoteBuf.
NTSTATUS AllocRemotePathBuffer(
    PEPROCESS process,
    PCWSTR    dllPath,
    SIZE_T    dllPathBytes,
    PVOID*    outRemoteBuf);

// Enfileira APC UserMode em `thread` executando `loadLibraryAddr(remotePathBuf)`.
// A KAPC (encapsulada em AffctlApc, veja inject.cpp) vai de NonPagedPool e e
// liberada na KernelRoutine (dispatch normal) ou na RundownRoutine (thread
// morreu antes da APC disparar).
//
// ownerProcess:
//   - nullptr  = caller compartilha o `remotePathBuf` entre multiplas APCs
//                (path watched — buffer vive com o processo alvo).
//   - non-null = caller transfere ownership do buffer para a APC. Se a thread
//                morrer antes da APC disparar, a RundownRoutine faz attach ao
//                processo e libera `remotePathBuf` via ZwFreeVirtualMemory
//                antes de largar a referencia. O caller NAO precisa (e nao
//                deve) fazer ObReferenceObject/Dereference — QueueLoadLibraryApc
//                assume a referencia internamente e a solta na kernel routine
//                ou na rundown routine.
NTSTATUS QueueLoadLibraryApc(
    PETHREAD  thread,
    PVOID     loadLibraryAddr,
    PVOID     remotePathBuf,
    PEPROCESS ownerProcess);

} // namespace affctl
