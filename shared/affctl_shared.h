// affctl_shared.h
// Contrato compartilhado entre o driver kernel (affctl.sys) e o app user-mode
// (affapp.exe). Fonte unica de verdade dos IOCTLs e structs de I/O.
//
// O driver define _KERNEL_MODE (o WDK define automaticamente em builds de driver).
#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

// -------- Nomes do device --------
#define AFFCTL_DEVICE_NAME   L"\\Device\\AffCtl"    // usado no kernel (IoCreateDevice)
#define AFFCTL_SYMLINK_NAME  L"\\??\\AffCtl"        // symlink (IoCreateSymbolicLink)
#define AFFCTL_USER_PATH     L"\\\\.\\AffCtl"       // caminho do app (CreateFileW)

// -------- IOCTLs (METHOD_BUFFERED, FILE_ANY_ACCESS) --------
// DIAG (Debug-only): despeja bytes crus da tagWND. Usado UMA VEZ na descoberta
// heuristica do offset da flag DisplayAffinity. Em Release o driver e compilado
// sem esse case — retorna STATUS_INVALID_DEVICE_REQUEST — pra nao servir como
// primitiva de info-leak de memoria kernel adjacente.
#define IOCTL_READ_RANGE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_OFFSET \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_AFFINITY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_AFFINITY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_GSHAREDINFO_ADDR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
// DIAG (Debug-only): despeja bytes crus de gSharedInfo, HANDLEENTRY e sondagens
// de phead. Mesma politica: gate em Release para nao vazar layouts internos do
// win32k.
#define IOCTL_AFF_DIAG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Endereco absoluto de win32kbase!ValidateHwnd (resolvido no app via PDB).
// Substitui a resolucao via aheList.phead (nao mais viavel a partir de Win11 25H2).
#define IOCTL_SET_VALIDATE_HWND \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Injeta uma DLL no processo alvo via APC no kernel (KeStackAttachProcess +
// ZwAllocateVirtualMemory + KeInsertQueueApc). O app resolve PID/TID/LoadLibraryW.
#define IOCTL_INJECT_DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Resolve PID mais recente por nome de executavel. Popula-se via callback
// PsSetCreateProcessNotifyRoutineEx (so ve processos criados APOS o driver).
#define IOCTL_RESOLVE_PID_BY_NAME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Registra "watch": todo processo futuro com esse basename (ou filho de um ja
// marcado) recebe injecao automatica no NASCIMENTO (via callback de thread).
#define IOCTL_WATCH_NAME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Remove um watch previamente registrado (matching por nome exato).
#define IOCTL_UNWATCH_NAME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Limite defensivo de bytes lidos da tagWND numa unica chamada de READ_RANGE.
// tagWND real ocupa ~0x300..0x400 bytes em Win10/11; 1024 e um teto generoso
// que ainda cabe dentro do objeto e nao extrapola pra estruturas adjacentes na
// session pool (evita info-leak). Historicamente era 8192 — reduzido no
// hardening pre-assinatura.
#define AFFCTL_MAX_RANGE 1024u

// -------- Structs de I/O --------
// HWND viaja como inteiro de 64 bits para ter layout identico em kernel e user.
#pragma pack(push, 1)

// IOCTL_READ_RANGE - input
typedef struct _READ_RANGE_INPUT {
    unsigned long long Hwnd;   // HWND do alvo (janela propria do app)
    unsigned long      Count;  // quantos bytes ler a partir do inicio da tagWND (<= AFFCTL_MAX_RANGE)
} READ_RANGE_INPUT, *PREAD_RANGE_INPUT;
// IOCTL_READ_RANGE - output: BYTE[Count]

// IOCTL_SET_OFFSET - input
// Em builds recentes (Win11 25H2+), a afinidade nao ocupa um byte inteiro:
// e um bit-flag dentro de um byte compartilhado com outras flags. O app manda o
// offset do byte E a mascara dos bits que WDA_EXCLUDEFROMCAPTURE liga (por
// exemplo 0x01). O driver limpa via `byte &= ~mask` para preservar o resto.
// ClearMask = 0xFF reproduz o comportamento antigo (byte inteiro).
typedef struct _SET_OFFSET_INPUT {
    unsigned long Offset;      // offset (em bytes) do byte-alvo dentro da tagWND
    unsigned char ClearMask;   // bits da afinidade dentro desse byte
    unsigned char _pad[3];
} SET_OFFSET_INPUT, *PSET_OFFSET_INPUT;

// IOCTL_CLEAR_AFFINITY / IOCTL_READ_AFFINITY - input
typedef struct _HWND_INPUT {
    unsigned long long Hwnd;
} HWND_INPUT, *PHWND_INPUT;

// IOCTL_READ_AFFINITY - output
typedef struct _READ_AFFINITY_OUTPUT {
    unsigned char Value;       // byte atual no offset (0x00 WDA_NONE / 0x01 WDA_MONITOR / 0x11 WDA_EXCLUDEFROMCAPTURE)
} READ_AFFINITY_OUTPUT, *PREAD_AFFINITY_OUTPUT;

// IOCTL_SET_GSHAREDINFO_ADDR - input
// Endereco absoluto de gSharedInfo no kernel, resolvido pelo app via
// (Base do win32kbase.sys) + (RVA de gSharedInfo obtido do PDB).
typedef struct _SET_GSHAREDINFO_INPUT {
    unsigned long long Address;
} SET_GSHAREDINFO_INPUT, *PSET_GSHAREDINFO_INPUT;

// IOCTL_SET_VALIDATE_HWND - input
typedef struct _SET_VALIDATE_HWND_INPUT {
    unsigned long long Address; // base(win32kbase.sys) + RVA(ValidateHwnd)
} SET_VALIDATE_HWND_INPUT, *PSET_VALIDATE_HWND_INPUT;

// Buffer estatico do nome do executavel usado no IOCTL_RESOLVE_PID_BY_NAME.
#define AFFCTL_MAX_IMAGE_NAME 128

// IOCTL_RESOLVE_PID_BY_NAME - input
typedef struct _RESOLVE_PID_INPUT {
    wchar_t       ImageName[AFFCTL_MAX_IMAGE_NAME]; // basename (ex: "afftarget.exe")
    unsigned long ImageNameLen;                     // bytes (sem NUL)
    unsigned long _pad;
} RESOLVE_PID_INPUT, *PRESOLVE_PID_INPUT;

// IOCTL_RESOLVE_PID_BY_NAME - output
typedef struct _RESOLVE_PID_OUTPUT {
    unsigned long long Pid; // 0 = nao encontrado
} RESOLVE_PID_OUTPUT, *PRESOLVE_PID_OUTPUT;

// IOCTL_WATCH_NAME - input
// Watch: driver auto-injeta a DLL em qualquer processo futuro que caia num destes:
//   a) basename == ImageName
//   b) ParentProcessId aponta pra um processo ja marcado (tree injection)
// Injecao acontece no callback de thread create -> APC antes do EntryPoint rodar.
//
// Fase B1: o trampolim shellcode chama ntdll!LdrLoadDll (nao mais kernel32!LoadLibraryW)
// pra fugir de allowlists triviais que assinam APCs com NormalRoutine em kernel32.
typedef struct _WATCH_NAME_INPUT {
    wchar_t            ImageName[AFFCTL_MAX_IMAGE_NAME]; // basename do EXE alvo
    unsigned long      ImageNameLen;                     // bytes (sem NUL)
    unsigned long      DllPathLen;                       // bytes (sem NUL)
    unsigned long long LdrLoadDllAddr;                   // ntdll!LdrLoadDll (VA no alvo)
    wchar_t            DllPath[520];                     // path absoluto da DLL
} WATCH_NAME_INPUT, *PWATCH_NAME_INPUT;

// IOCTL_UNWATCH_NAME - input
typedef struct _UNWATCH_NAME_INPUT {
    wchar_t       ImageName[AFFCTL_MAX_IMAGE_NAME];
    unsigned long ImageNameLen;
    unsigned long _pad;
} UNWATCH_NAME_INPUT, *PUNWATCH_NAME_INPUT;

// IOCTL_INJECT_DLL - input
// LdrLoadDll e resolvido no lado user (ntdll e Known DLL: mesmo VA em todos
// processos da mesma sessao / boot). O driver so executa: attach + criar section
// com shellcode+path + mapear no alvo + queue APC apontando pro trampolim.
typedef struct _INJECT_DLL_INPUT {
    unsigned long long TargetPid;        // PID do processo alvo
    unsigned long long TargetTid;        // TID de uma thread do alvo (GUI = alertable rapido)
    unsigned long long LdrLoadDllAddr;   // Endereco de ntdll!LdrLoadDll (VA no alvo)
    unsigned long      DllPathLen;       // Bytes do path (WCHAR count * 2), sem NUL
    unsigned long      _pad;
    wchar_t            DllPath[520];     // Path da DLL (max ~260 WCHARs = MAX_PATH)
} INJECT_DLL_INPUT, *PINJECT_DLL_INPUT;

// IOCTL_AFF_DIAG - input: HWND_INPUT ; output: AFF_DIAG_OUTPUT
// Despejo cru (layout-agnostico) para diagnosticar a resolucao HWND->tagWND.
typedef struct _AFF_DIAG_OUTPUT {
    unsigned long long gShared;      // valor de g_pSharedInfo no driver
    unsigned long      gSharedValid; // MmIsAddressValid(gShared)
    unsigned long      index;        // hwnd & 0xFFFF
    unsigned long long aheListPtr;   // *(u64*)(gShared + 0x08)
    unsigned long      heEntrySize;  // *(u32*)(gShared + 0x10)
    unsigned long      aheListValid; // MmIsAddressValid(aheListPtr)
    unsigned long long hePtr;        // aheListPtr + index * heEntrySize
    unsigned long      heValid;      // MmIsAddressValid(hePtr)
    unsigned char      bType;        // entry[0x18] observado (layout Win11 25H2)
    unsigned char      bFlags;       // entry[0x19]
    unsigned short     wUniq;        // entry[0x1A]
    unsigned char      gSharedRaw[128]; // 128 bytes crus a partir de gShared
    unsigned char      heRaw[128];      // 128 bytes crus a partir de hePtr (4 entries de 32B)
    // Sondagem do phead: testamos varias hipoteses de decodificacao. Para cada
    // candidato, guardamos o endereco tentado, se e mapeado, e 32 bytes crus.
    unsigned long long pheadCand[4]; // 0=raw, 1=|win32kbase_high, 2=|psi_high, 3=|aheList_high
    unsigned long      pheadValid[4];
    unsigned char      pheadRaw[4][32];
} AFF_DIAG_OUTPUT, *PAFF_DIAG_OUTPUT;

#pragma pack(pop)
