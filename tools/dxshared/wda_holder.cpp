// wda_holder — cria janela colorida, aplica WDA, escreve HWND em arquivo,
// e fica vivo ate WM_CLOSE (Ctrl+C do launcher OU kill process).
//
// Uso: wda_holder.exe <mode:none|monitor|exclude> <hwnd_out_file>
//
// Compile: cl /nologo /EHsc /std:c++17 /O2 wda_holder.cpp /link user32.lib gdi32.lib /OUT:wda_holder.exe /SUBSYSTEM:CONSOLE

#include <windows.h>
#include <cstdio>
#include <cstdint>

#ifndef WDA_MONITOR
#define WDA_MONITOR 1
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x11
#endif

static DWORD g_mode = 0;

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(h, &ps);
        RECT rc; GetClientRect(h, &rc);
        int cw = rc.right / 8, ch = rc.bottom / 6;
        COLORREF colors[] = {
            RGB(255,0,0), RGB(0,255,0), RGB(0,0,255), RGB(255,255,0),
            RGB(255,0,255), RGB(0,255,255), RGB(255,128,0), RGB(128,0,255)
        };
        for (int y=0;y<6;++y) for (int x=0;x<8;++x) {
            HBRUSH br = CreateSolidBrush(colors[(x + y*8) % 8]);
            RECT r{ x*cw, y*ch, (x+1)*cw, (y+1)*ch };
            FillRect(hdc, &r, br); DeleteObject(br);
        }
        SetBkMode(hdc, TRANSPARENT); SetTextColor(hdc, RGB(255,255,255));
        HFONT font = CreateFontW(64, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        HGDIOBJ oldF = SelectObject(hdc, font);
        const wchar_t* s =
            g_mode == 0 ? L"WDA_NONE" :
            g_mode == WDA_MONITOR ? L"WDA_MONITOR" :
            g_mode == WDA_EXCLUDEFROMCAPTURE ? L"WDA_EXCLUDEFROMCAPTURE" : L"???";
        RECT tr = rc; tr.top = 40;
        DrawTextW(hdc, s, -1, &tr, DT_CENTER | DT_TOP);
        SelectObject(hdc, oldF); DeleteObject(font);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProc(h, m, wp, lp);
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        printf("Uso: wda_holder.exe <mode:none|monitor|exclude> <hwnd_out_file>\n");
        return 1;
    }
    if (!_wcsicmp(argv[1], L"none")) g_mode = 0;
    else if (!_wcsicmp(argv[1], L"monitor")) g_mode = WDA_MONITOR;
    else if (!_wcsicmp(argv[1], L"exclude")) g_mode = WDA_EXCLUDEFROMCAPTURE;
    else { printf("modo desconhecido\n"); return 1; }

    const wchar_t* outFile = argv[2];

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = L"WDA_HOLDER_CLASS";
    RegisterClassW(&wc);

    HWND h = CreateWindowExW(0, L"WDA_HOLDER_CLASS", L"WDA_HOLDER_WINDOW",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        100, 100, 800, 600,
        nullptr, nullptr, wc.hInstance, nullptr);
    if (!h) { printf("CreateWindow FAIL %lu\n", GetLastError()); return 2; }

    BOOL wok = SetWindowDisplayAffinity(h, g_mode);
    DWORD after = 0xDEAD; GetWindowDisplayAffinity(h, &after);
    printf("HWND=%p WDA_set(%lu)->%s after=%lu\n", h, g_mode, wok ? "OK" : "FAIL", after);

    ShowWindow(h, SW_SHOW); UpdateWindow(h);

    // Escreve HWND em arquivo (hex, um por linha)
    FILE* f = nullptr; _wfopen_s(&f, outFile, L"wb");
    if (f) {
        char buf[64]; snprintf(buf, sizeof(buf), "%p\n", h);
        fwrite(buf, 1, strlen(buf), f); fclose(f);
    }

    // Loop de mensagens ate WM_CLOSE
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg); DispatchMessage(&msg);
    }
    return 0;
}
