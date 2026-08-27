// process_notify.h
// Rastreio event-driven de processos via PsSetCreateProcessNotifyRoutineEx.
// O kernel invoca nosso callback a cada CreateProcess/ExitProcess, e nos
// mantemos uma tabela pequena de {basename -> PID} para resolver alvos
// pelo nome do executavel (util pra IOCTL_INJECT_BY_NAME e afins).
//
// Requisitos:
//   - Driver linkado com /INTEGRITYCHECK (senao Ex-variant retorna erro).
//   - Cleanup obrigatorio no DriverUnload (antes de IoDeleteDevice).
#pragma once
#include <ntddk.h>

namespace affctl {

// Inicializa tabela + registra callback. Chame do DriverEntry apos
// IoCreateDevice/IoCreateSymbolicLink.
NTSTATUS ProcessNotifyInit();

// Desregistra callback e limpa estado. Chame do Unload ANTES do IoDeleteDevice
// — se ha um callback pending, remove-lo antes evita BSOD por use-after-unload.
void ProcessNotifyCleanup();

// Resolve PID do processo MAIS RECENTE com esse basename (case-insensitive).
// Retorna nullptr se nao houver match no historico registrado pelo callback.
// Nota: so ve processos criados APOS o driver carregar.
HANDLE ResolvePidByName(PCWSTR imageName);

// Registra um watch: todo processo futuro cujo basename == imageName (ou cujo
// PAI ja esteja marcado — tree injection) recebe injecao automatica de
// `dllPath` via APC no callback de thread create.
NTSTATUS AddWatch(
    PCWSTR imageName,
    PCWSTR dllPath,
    ULONG  dllPathBytes,
    PVOID  loadLibraryAddr);

// Remove um watch por nome exato. Marca processos ja injetados como nao mais
// monitorados (nao remove a DLL que ja carregou).
NTSTATUS RemoveWatch(PCWSTR imageName);

} // namespace affctl
