// afftarget.cpp
// Cobaia para o teste de bypass do DisplayAffinity. Cria uma janela visivel
// com conteudo distintivo e dois botoes:
//   [ Proteger ]      -> SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)
//   [ Ler afinidade ] -> GetWindowDisplayAffinity(...) e mostra na barra
//
// Fluxo esperado da demo:
//   1) Abre afftarget.exe, clica em "Proteger".
//   2) Snipping Tool captura -> janela aparece PRETA (protecao ativa).
//   3) affapp.exe --inject <PID> affbypass.dll (injeta o hook via APC kernel).
//   4) Clica em "Proteger" de novo -> hook retorna TRUE, mas nao chama o
//      Windows -> Snipping Tool captura o CONTEUDO REAL.
#include <windows.h>
#include <cstdio>

#ifndef WDA_NONE
#define WDA_NONE 0x00
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x11
#endif

namespace {

constexpr int ID_BTN_PROTECT = 1001;
constexpr int ID_BTN_READ    = 1002;
constexpr int ID_STATUS      = 1003;

HWND g_status = nullptr;

void updateStatus(HWND hwnd) {
    DWORD aff = 0;
    GetWindowDisplayAffinity(hwnd, &aff);
    wchar_t buf[128];
    wsprintfW(buf, L"Afinidade atual: 0x%02X  %s",
              aff,
              (aff == WDA_NONE)              ? L"(WDA_NONE — sem protecao)" :
              (aff == 0x01)                  ? L"(WDA_MONITOR)" :
              (aff == WDA_EXCLUDEFROMCAPTURE)? L"(WDA_EXCLUDEFROMCAPTURE)" :
                                               L"(desconhecido)");
    SetWindowTextW(g_status, buf);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        CreateWindowW(L"BUTTON", L"Proteger (WDA_EXCLUDEFROMCAPTURE)",
                      WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                      20, 20, 300, 30, hwnd, (HMENU)ID_BTN_PROTECT,
                      (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE), nullptr);
        CreateWindowW(L"BUTTON", L"Ler afinidade",
                      WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                      340, 20, 150, 30, hwnd, (HMENU)ID_BTN_READ,
                      (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE), nullptr);
        g_status = CreateWindowW(L"STATIC", L"Afinidade atual: (leia)",
                      WS_VISIBLE | WS_CHILD | SS_LEFT,
                      20, 60, 470, 20, hwnd, (HMENU)ID_STATUS,
                      (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE), nullptr);
        updateStatus(hwnd);
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_BTN_PROTECT:
            SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
            updateStatus(hwnd);
            return 0;
        case ID_BTN_READ:
            updateStatus(hwnd);
            return 0;
        }
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);
        // Fundo com listras coloridas — instantaneamente identificavel numa
        // captura de tela (antes/depois do bypass).
        HBRUSH b1 = CreateSolidBrush(RGB(0xE8, 0x2B, 0x2B));
        HBRUSH b2 = CreateSolidBrush(RGB(0x2B, 0xB8, 0x4B));
        HBRUSH b3 = CreateSolidBrush(RGB(0x2B, 0x5B, 0xE8));
        RECT r = rc; r.top = 100; r.bottom = 160; FillRect(dc, &r, b1);
        r.top = 160; r.bottom = 220; FillRect(dc, &r, b2);
        r.top = 220; r.bottom = 280; FillRect(dc, &r, b3);
        DeleteObject(b1); DeleteObject(b2); DeleteObject(b3);
        // Texto grande no centro.
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(0xFF, 0xFF, 0xFF));
        HFONT font = CreateFontW(-32, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");
        HGDIOBJ old = SelectObject(dc, font);
        r = rc; r.top = 160;
        DrawTextW(dc, L"AffCtl TARGET", -1, &r,
                  DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        SelectObject(dc, old);
        DeleteObject(font);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

} // namespace

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    WNDCLASSW wc{};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"AffCtlTargetClass";
    if (!RegisterClassW(&wc)) return 1;

    HWND hwnd = CreateWindowExW(
        0, wc.lpszClassName, L"AffCtl Target — teste de bypass",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 520, 340,
        nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 2;

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    // Console anexo pra logar PID (util pra passar pro injector).
    wchar_t title[128];
    wsprintfW(title, L"AffCtl Target — PID %u", GetCurrentProcessId());
    SetWindowTextW(hwnd, title);

    // Loop de mensagens ALERTABLE — MsgWaitForMultipleObjectsEx com MWMO_ALERTABLE
    // faz a thread entrar em wait alertable entre mensagens. Isso garante que
    // APCs user-mode enfileiradas pelo driver disparem imediatamente (necessario
    // pra receber a DLL de bypass injetada via IOCTL_INJECT_DLL).
    for (;;) {
        DWORD r = MsgWaitForMultipleObjectsEx(0, nullptr, INFINITE,
                                              QS_ALLINPUT, MWMO_ALERTABLE);
        if (r == WAIT_IO_COMPLETION) {
            // Uma APC (ex: LoadLibraryW da nossa DLL) acabou de rodar. Segue.
            continue;
        }
        if (r == WAIT_OBJECT_0) {
            MSG msg;
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) return (int)msg.wParam;
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}
