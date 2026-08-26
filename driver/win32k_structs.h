// win32k_structs.h
// Layout PARCIAL de estruturas nao-documentadas do subsistema GUI do Windows
// (win32k). Somente os campos que este driver usa.
//
// IMPORTANTE: estes layouts NAO sao contrato estavel da Microsoft. Os offsets
// de aheList dentro de SHAREDINFO e o layout de HANDLEENTRY foram estaveis por
// varias versoes de Windows 10/11 x64, mas DEVEM ser validados na build alvo com
// WinDbg antes de confiar (ver README, secao "Pattern e validacao de structs").
#pragma once
#include <ntddk.h>

// -------- HANDLEENTRY --------
// Cada handle de objeto do win32k (janela, menu, cursor, etc.) tem uma entrada
// nesta tabela. Para uma janela (HWND), 'phead' aponta para a estrutura do
// objeto no kernel, cujo inicio corresponde a tagWND (via _HEAD/_THRDESKHEAD).
typedef struct _HANDLEENTRY {
    PVOID          phead;   // ponteiro para o objeto no kernel (tagWND para janelas)
    PVOID          pOwner;  // dono do objeto (thread/process info)
    unsigned char  bType;   // tipo do objeto (TYPE_WINDOW == 1)
    unsigned char  bFlags;
    unsigned short wUniq;
} HANDLEENTRY, *PHANDLEENTRY;

#define TYPE_WINDOW 1

// -------- SHAREDINFO --------
// Estrutura global do win32k (gSharedInfo). 'aheList' e o array de HANDLEENTRY.
// Demais campos omitidos por nao serem usados.
typedef struct _SERVERINFO SERVERINFO, *PSERVERINFO;

typedef struct _SHAREDINFO {
    PSERVERINFO    psi;         // server info
    PHANDLEENTRY   aheList;     // array de HANDLEENTRY (tabela de handles)
    unsigned long  HeEntrySize; // sizeof(HANDLEENTRY) reportado pelo win32k
    // ... campos restantes omitidos (nao usados)
} SHAREDINFO, *PSHAREDINFO;

// Indice do handle a partir do HWND: os 16 bits baixos indexam aheList.
#define HWND_INDEX(h) ((unsigned long)((ULONG_PTR)(h) & 0xFFFF))
