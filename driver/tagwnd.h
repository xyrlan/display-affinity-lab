// tagwnd.h
// Resolucao HWND -> ponteiro tagWND no kernel e acesso guardado (SEH) a bytes
// da tagWND. Toda desreferencia de ponteiro kernel ocorre sob __try/__except
// na implementacao — nenhuma destas funcoes causa BSOD em ponteiro invalido.
#pragma once
#include <ntddk.h>

namespace affctl {

// Localiza gSharedInfo uma unica vez (cacheado). Idempotente.
// Retorna STATUS_SUCCESS, ou STATUS_NOT_FOUND se o pattern scan falhar.
NTSTATUS InitSharedInfo();

// Resolve HWND -> ponteiro para a tagWND no kernel. Retorna nullptr se o handle
// for invalido, nao for janela, ou gSharedInfo nao tiver sido localizado.
PVOID ResolveTagWnd(ULONG_PTR hwnd);

// Le 'count' bytes a partir do inicio da tagWND para 'out'. Guardado por SEH.
// count deve ser <= AFFCTL_MAX_RANGE (validado pelo chamador no dispatch).
NTSTATUS ReadTagWndRange(ULONG_PTR hwnd, PVOID out, ULONG count);

// Le 1 byte no 'offset' da tagWND para *value. Guardado por SEH.
NTSTATUS ReadFlag(ULONG_PTR hwnd, ULONG offset, unsigned char* value);

// Escreve 0x00 (WDA_NONE) no 'offset' da tagWND. Guardado por SEH.
NTSTATUS ClearFlag(ULONG_PTR hwnd, ULONG offset);

} // namespace affctl
