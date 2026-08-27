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

} // namespace affctl
