// tagwnd.h
// Resolucao HWND -> ponteiro tagWND no kernel e acesso guardado (SEH) a bytes
// da tagWND. Toda desreferencia de ponteiro kernel ocorre sob __try/__except
// na implementacao — nenhuma destas funcoes causa BSOD em ponteiro invalido.
#pragma once
#include <ntddk.h>

namespace affctl {

// Recebe o endereco absoluto de gSharedInfo (calculado no user-mode via
// base(win32kbase.sys) + RVA(gSharedInfo) do PDB). Deve ser chamado uma vez
// antes de qualquer resolucao. Substitui o antigo pattern-scan stub.
// Retorna STATUS_INVALID_PARAMETER se addr for nulo/invalido.
NTSTATUS SetSharedInfoAddress(PVOID addr);

// Recebe o endereco absoluto de win32kbase!ValidateHwnd (resolvido pelo app via
// PDB). Prioridade sobre o caminho aheList.phead — a Microsoft escondeu phead da
// HANDLEENTRY publica em builds recentes; ValidateHwnd continua sendo o
// resolvedor oficial HWND->PWND.
NTSTATUS SetValidateHwndAddress(PVOID addr);

// Valida se gSharedInfo ja foi configurado. STATUS_SUCCESS se sim,
// STATUS_INVALID_DEVICE_STATE se ainda nao.
NTSTATUS InitSharedInfo();

// Resolve HWND -> ponteiro para a tagWND no kernel. Retorna nullptr se o handle
// for invalido, nao for janela, ou gSharedInfo nao tiver sido localizado.
PVOID ResolveTagWnd(ULONG_PTR hwnd);

// Le 'count' bytes a partir do inicio da tagWND para 'out'. Guardado por SEH.
// count deve ser <= AFFCTL_MAX_RANGE (validado pelo chamador no dispatch).
NTSTATUS ReadTagWndRange(ULONG_PTR hwnd, PVOID out, ULONG count);

// Le 1 byte no 'offset' da tagWND para *value. Guardado por SEH.
NTSTATUS ReadFlag(ULONG_PTR hwnd, ULONG offset, unsigned char* value);

// Limpa os bits de 'mask' no byte em 'offset' da tagWND (byte &= ~mask).
// mask=0xFF equivale a zerar o byte todo (comportamento antigo). Guardado por SEH.
NTSTATUS ClearFlag(ULONG_PTR hwnd, ULONG offset, unsigned char mask);

// Diagnostico: preenche AFF_DIAG_OUTPUT (passado como void*) com despejo cru de
// gSharedInfo e da entrada de handle calculada. Layout-agnostico, guardado por SEH.
NTSTATUS Diag(ULONG_PTR hwnd, void* out);

} // namespace affctl
