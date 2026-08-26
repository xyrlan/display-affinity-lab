// TestWindow.cpp
#include "TestWindow.hpp"
#include <system_error>

const wchar_t* TestWindow::kClassName = L"AffCtlTestWindowClass";
bool TestWindow::s_classRegistered = false;

LRESULT CALLBACK TestWindow::WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        // Fundo distintivo + texto, para a prova visual before/after ficar obvia.
        HBRUSH bg = CreateSolidBrush(RGB(20, 120, 220));
        FillRect(hdc, &rc, bg);
        DeleteObject(bg);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));
        const wchar_t* text = L"AffCtl DEMO — se voce ve isto numa captura, WDA_NONE aplicado";
        DrawTextW(hdc, text, -1, &rc,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_WORDBREAK);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

TestWindow::TestWindow(bool visible, const wchar_t* title) {
    HINSTANCE hInst = GetModuleHandleW(nullptr);

    if (!s_classRegistered) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = &TestWindow::WndProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = kClassName;
        if (RegisterClassExW(&wc) == 0) {
            throw std::system_error(static_cast<int>(GetLastError()),
                                    std::system_category(), "RegisterClassExW");
        }
        s_classRegistered = true;
    }

    DWORD style = WS_OVERLAPPEDWINDOW;
    m_hwnd = CreateWindowExW(
        0, kClassName, title, style,
        CW_USEDEFAULT, CW_USEDEFAULT, 560, 200,
        nullptr, nullptr, hInst, nullptr);
    if (m_hwnd == nullptr) {
        throw std::system_error(static_cast<int>(GetLastError()),
                                std::system_category(), "CreateWindowExW");
    }

    if (visible) {
        ShowWindow(m_hwnd, SW_SHOW);
        UpdateWindow(m_hwnd);
    }
    // Janela oculta: nao chamamos ShowWindow; ela existe mas nao aparece.
    pump();
}

TestWindow::~TestWindow() {
    if (m_hwnd != nullptr) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void TestWindow::setAffinity(DWORD mode) {
    if (!SetWindowDisplayAffinity(m_hwnd, mode)) {
        throw std::system_error(static_cast<int>(GetLastError()),
                                std::system_category(), "SetWindowDisplayAffinity");
    }
}

void TestWindow::pump() {
    MSG msg;
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}
