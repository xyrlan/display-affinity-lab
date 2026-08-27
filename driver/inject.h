// inject.h
// Injecao de DLL em processo user-mode via APC do kernel.
// Tecnica (Fase B1): section anonima RWX-max carregando shellcode trampolim +
// UNICODE_STRING + path da DLL, mapeada RX no alvo. A APC user-mode aponta
// NormalRoutine == NormalContext == remoteBase (offset 0 = entry do trampolim).
// O trampolim chama ntdll!LdrLoadDll(NULL, NULL, &UNICODE_STRING, &out).
//
// Por que trampolim + LdrLoadDll em vez de NormalRoutine = kernel32!LoadLibraryW:
//   - APC dispatcher hook (KiInitializeUserApc / KiDeliverApc) que classifica
//     NormalRoutine por modulo (kernel32 = suspeito) nao dispara — a routine
//     agora aponta pra dentro da nossa section (nao mapeada como imagem).
//   - LdrLoadDll e o primitivo interno usado pelo proprio loader do Windows;
//     e chamado o tempo todo em qualquer processo — se mistura com traffic legitimo.
//
// Requisitos operacionais:
//   - IRQL = PASSIVE_LEVEL (usa Zw*Section, ExAllocatePool2, attach de processo)
//   - Alvo user-mode x64; se for GUI, APC dispara na proxima wait alertable.
//   - ldrLoadDllAddr resolvido pelo caller (user-mode ou driver) via
//     ntdll — Known DLL, VA identico em todos processos da sessao (per-boot ASLR).
#pragma once
#include <ntddk.h>

namespace affctl {

// Enfileira APC user-mode em `tid` (thread de `pid`) que executa o trampolim
// shellcode no contexto do alvo, chamando `ldrLoadDllAddr(NULL, NULL, &UNICODE_STRING(dllPath), &out)`.
// Nao bloqueia — retorna quando a APC foi enfileirada; o trampolim roda quando
// a thread entra em wait alertable.
//
// dllPathBytes = comprimento em BYTES do path (sem NUL terminator).
// Toda desreferencia de memoria potencialmente invalida esta sob __try/__except.
NTSTATUS InjectDll(
    HANDLE pid,
    HANDLE tid,
    PVOID  ldrLoadDllAddr,
    PCWSTR dllPath,
    SIZE_T dllPathBytes);

// Constroi section anonima RWX-max com layout:
//   [+0x00] trampolim x64 (~42 B)
//   [+0x80] ldrLoadDllAddr (patched — call qword ptr [rbx+0x80])
//   [+0x90] UNICODE_STRING { Length, MaximumLength, pad, Buffer=remoteBase+0xA0 }
//   [+0xA0] wide path null-terminado
//
// Passos:
//   1. ZwCreateSection (SEC_COMMIT, PAGE_EXECUTE_READWRITE max prot).
//   2. Mapeia local RW (System VA).
//   3. Mapeia remoto RX no alvo (attach + ZwMapViewOfSection PAGE_EXECUTE_READ)
//      — precisamos do remoteBase ANTES de escrever, pra montar UNICODE_STRING.Buffer.
//   4. Escreve payload via view local (mesmas paginas fisicas → visivel no alvo).
//   5. Unmap local + ZwClose(hSec) — view remota mantem section object viva.
//
// Assume PASSIVE_LEVEL e contexto de thread nao-arbitraria (pode fazer attach).
// Retorna o remoteBase (VA do trampolim no alvo) em *outRemoteBase — usar como
// NormalRoutine E NormalContext da APC.
NTSTATUS AllocRemotePathBuffer(
    PEPROCESS process,
    PCWSTR    dllPath,
    SIZE_T    dllPathBytes,
    PVOID     ldrLoadDllAddr,
    PVOID*    outRemoteBase);

// Enfileira APC UserMode em `thread` executando o trampolim em `remoteBase`.
// NormalRoutine = NormalContext = remoteBase — o trampolim recebe o base em RCX
// e navega pelos offsets do layout pra achar LdrLoadDllAddr e UNICODE_STRING.
// A KAPC (encapsulada em AffctlApc, veja inject.cpp) vai de NonPagedPool e e
// liberada na KernelRoutine (dispatch normal) ou na RundownRoutine (thread
// morreu antes da APC disparar).
//
// ownerProcess:
//   - nullptr  = caller compartilha `remoteBase` entre multiplas APCs
//                (path watched — view vive com o processo alvo).
//   - non-null = caller transfere ownership da view para a APC. Se a thread
//                morrer antes da APC disparar, a RundownRoutine faz attach ao
//                processo e desmapeia `remoteBase` via ZwUnmapViewOfSection
//                antes de largar a referencia — o Mm libera o section object
//                junto porque essa era a ultima view. O caller NAO precisa (e
//                nao deve) fazer ObReferenceObject/Dereference — QueueLoadLibraryApc
//                assume a referencia internamente e a solta na kernel routine
//                ou na rundown routine.
NTSTATUS QueueLoadLibraryApc(
    PETHREAD  thread,
    PVOID     remoteBase,
    PEPROCESS ownerProcess);

} // namespace affctl
