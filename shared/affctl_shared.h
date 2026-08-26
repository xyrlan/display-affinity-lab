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

// Limite defensivo de bytes lidos da tagWND numa unica chamada de READ_RANGE.
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
typedef struct _SET_OFFSET_INPUT {
    unsigned long Offset;      // offset (em bytes) da flag DisplayAffinity dentro da tagWND
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

#pragma pack(pop)
