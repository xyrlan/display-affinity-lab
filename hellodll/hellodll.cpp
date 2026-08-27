// hellodll.cpp
// DLL de teste para o pipeline de injecao via APC. Ao ser carregada dentro do
// processo alvo (LoadLibraryW disparado pela APC), mostra um MessageBox com
// o PID atual — prova visual de que:
//   1. A APC executou no contexto do alvo.
//   2. LoadLibraryW recebeu o path certo.
//   3. A DLL carregou com sucesso.
//
// Fluxo esperado (dentro da VM):
//   [ target ] cria janela GUI, entra no message loop (wait alertable)
//   [ affapp --inject ] driver enfileira APC
//   [ target thread ]   APC dispara -> LoadLibraryW("...\hellodll.dll")
//   [ hellodll DllMain] MessageBox("hellodll injected! PID=...")

#include <windows.h>

// Escreve um arquivo curto — prova incondicional (nao depende de UI/desktop).
// Usa %TEMP%, que e sempre acessivel independente do IL do processo alvo.
static void writeProofFile() {
    wchar_t path[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, path);
    if (n == 0 || n >= MAX_PATH - 32) return;
    lstrcatW(path, L"hellodll_loaded.txt");

    HANDLE h = CreateFileW(path,
                           GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        // Fallback: OutputDebugString (aparece em DebugView).
        OutputDebugStringW(L"hellodll: DllMain rodou mas nao consegui abrir arquivo");
        return;
    }
    SYSTEMTIME st; GetLocalTime(&st);
    char line[256];
    int len = wsprintfA(line,
        "hellodll DllMain rodou\r\nPID do host: %u\r\nHora: %04u-%02u-%02u %02u:%02u:%02u\r\n",
        GetCurrentProcessId(),
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    DWORD w = 0;
    WriteFile(h, line, (DWORD)len, &w, nullptr);
    CloseHandle(h);
    OutputDebugStringW(L"hellodll: file written to %TEMP%");
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst); // sem callbacks por-thread
        writeProofFile();
        // MessageBox e prova bonita mas depende de acesso a interactive desktop.
        // Mesmo se essa parte falhar, o arquivo acima ja confirma o DllMain.
        wchar_t msg[128];
        wsprintfW(msg,
                  L"hellodll carregado via APC!\n\nPID do host: %u",
                  GetCurrentProcessId());
        MessageBoxW(nullptr, msg, L"AffCtl Injection Test",
                    MB_OK | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND |
                    MB_SERVICE_NOTIFICATION);
    }
    return TRUE;
}
