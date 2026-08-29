// wgc_selftest — cria janela propria colorida, aplica WDA opcional, captura via WGC
// Uso: wgc_selftest.exe <mode> <out_prefix>
//   mode = none | monitor | exclude
// Salva <out>.wgc.bmp + verdict.
//
// Compile: cl /nologo /EHsc /std:c++20 /O2 wgc_selftest.cpp /link ^
//   d3d11.lib dxgi.lib user32.lib gdi32.lib windowsapp.lib runtimeobject.lib ^
//   /OUT:wgc_selftest.exe /SUBSYSTEM:CONSOLE

#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <atomic>

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Graphics.h>
#include <winrt/Windows.Graphics.Capture.h>
#include <winrt/Windows.Graphics.DirectX.h>
#include <winrt/Windows.Graphics.DirectX.Direct3D11.h>

#include <windows.graphics.capture.interop.h>
#include <windows.graphics.directx.direct3d11.interop.h>

using Microsoft::WRL::ComPtr;
namespace wgcap = winrt::Windows::Graphics::Capture;
namespace wgdxd3d = winrt::Windows::Graphics::DirectX::Direct3D11;

#ifndef WDA_MONITOR
#define WDA_MONITOR 1
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x11
#endif

static DWORD g_mode = 0;
static HWND g_hwnd = nullptr;
static std::atomic<bool> g_ready{ false };

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(h, &ps);
        RECT rc; GetClientRect(h, &rc);
        // Padrao xadrez colorido
        int cw = rc.right / 8, ch = rc.bottom / 6;
        COLORREF colors[] = {
            RGB(255,0,0), RGB(0,255,0), RGB(0,0,255), RGB(255,255,0),
            RGB(255,0,255), RGB(0,255,255), RGB(255,128,0), RGB(128,0,255)
        };
        for (int y = 0; y < 6; ++y) for (int x = 0; x < 8; ++x) {
            HBRUSH br = CreateSolidBrush(colors[(x + y * 8) % 8]);
            RECT r{ x*cw, y*ch, (x+1)*cw, (y+1)*ch };
            FillRect(hdc, &r, br); DeleteObject(br);
        }
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255,255,255));
        HFONT font = CreateFontW(48, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        HGDIOBJ oldF = SelectObject(hdc, font);
        const wchar_t* modeStr =
            g_mode == 0 ? L"WDA_NONE" :
            g_mode == WDA_MONITOR ? L"WDA_MONITOR" :
            g_mode == WDA_EXCLUDEFROMCAPTURE ? L"WDA_EXCLUDEFROMCAPTURE" : L"???";
        RECT tr = rc; tr.top = 30;
        DrawTextW(hdc, modeStr, -1, &tr, DT_CENTER | DT_TOP);
        SelectObject(hdc, oldF); DeleteObject(font);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProc(h, m, wp, lp);
}

static void windowThread() {
    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = L"WGC_SELF_CLASS";
    RegisterClassW(&wc);

    g_hwnd = CreateWindowExW(0, L"WGC_SELF_CLASS", L"WGC_SELFTEST",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        100, 100, 800, 600,
        nullptr, nullptr, wc.hInstance, nullptr);

    if (!g_hwnd) {
        fprintf(stderr, "[!] CreateWindow FAIL err=%lu\n", GetLastError());
        g_ready = true;
        return;
    }

    // Aplica WDA no proprio hwnd (mesmo processo -> permitido)
    BOOL wda_ok = SetWindowDisplayAffinity(g_hwnd, g_mode);
    DWORD after = 0xDEAD; GetWindowDisplayAffinity(g_hwnd, &after);
    printf("[self] CreateWindow HWND=%p WDA_set(%lu)->%s after=%lu\n",
        g_hwnd, g_mode, wda_ok ? "OK" : "FAIL", after);
    if (!wda_ok) printf("  err=%lu\n", GetLastError());

    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    g_ready = true;

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg); DispatchMessage(&msg);
    }
}

// -------- utils --------
static bool saveBmp(const char* p, const uint8_t* bgra, int w, int h, int st) {
    BITMAPFILEHEADER fh{}; BITMAPINFOHEADER ih{};
    fh.bfType = 0x4D42; fh.bfOffBits = sizeof(fh) + sizeof(ih);
    fh.bfSize = fh.bfOffBits + w * h * 4;
    ih.biSize = sizeof(ih); ih.biWidth = w; ih.biHeight = -h;
    ih.biPlanes = 1; ih.biBitCount = 32; ih.biCompression = BI_RGB;
    ih.biSizeImage = w * h * 4;
    FILE* f = nullptr; fopen_s(&f, p, "wb");
    if (!f) return false;
    fwrite(&fh, 1, sizeof(fh), f); fwrite(&ih, 1, sizeof(ih), f);
    for (int y = 0; y < h; ++y) fwrite(bgra + y * st, 1, w * 4, f);
    fclose(f); return true;
}
struct Stats { double mean, stdev; int blackPct, nonZ; };
static Stats analyze(const uint8_t* p, int w, int h, int st) {
    double s = 0, s2 = 0; int b = 0, nz = 0; int64_t n = int64_t(w) * h;
    for (int y = 0; y < h; ++y) {
        const uint8_t* r = p + y * st;
        for (int x = 0; x < w; ++x) {
            uint8_t bb = r[x*4], gg = r[x*4+1], rr = r[x*4+2];
            if (bb || gg || rr) ++nz;
            double lu = 0.299*rr + 0.587*gg + 0.114*bb;
            s += lu; s2 += lu * lu;
            if (lu < 8) ++b;
        }
    }
    double m = s / n; double v = s2 / n - m * m;
    return { m, v > 0 ? sqrt(v) : 0, int(100.0 * b / n), nz };
}
static void verdict(const char* lbl, Stats s, int w, int h) {
    printf("[%s] %dx%d mean=%.2f stdev=%.2f black%%=%d nonzero=%d/%lld\n",
        lbl, w, h, s.mean, s.stdev, s.blackPct, s.nonZ, int64_t(w)*h);
    if (s.mean < 4.0 && s.blackPct > 95) printf("    -> PRETO (WDA honrado)\n");
    else if (s.mean > 20.0 && s.blackPct < 50) printf("    -> FRAME REAL\n");
    else printf("    -> AMBIGUO\n");
}

static bool captureWGC(HWND hwnd, std::vector<uint8_t>& out, int& W, int& H) {
    ComPtr<ID3D11Device> d3d; ComPtr<ID3D11DeviceContext> ctx;
    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        0, nullptr, 0, D3D11_SDK_VERSION, &d3d, &fl, &ctx);
    if (FAILED(hr)) { printf("[!] D3D 0x%lX\n", hr); return false; }

    ComPtr<IDXGIDevice> dxgi; d3d.As(&dxgi);
    winrt::com_ptr<::IInspectable> insp;
    hr = CreateDirect3D11DeviceFromDXGIDevice(dxgi.Get(), insp.put());
    if (FAILED(hr)) { printf("[!] Interop 0x%lX\n", hr); return false; }
    auto idev = insp.as<wgdxd3d::IDirect3DDevice>();

    auto fac = winrt::get_activation_factory<wgcap::GraphicsCaptureItem, IGraphicsCaptureItemInterop>();
    wgcap::GraphicsCaptureItem item{ nullptr };
    hr = fac->CreateForWindow(hwnd, winrt::guid_of<wgcap::GraphicsCaptureItem>(), winrt::put_abi(item));
    if (FAILED(hr)) { printf("[!] CreateForWindow 0x%lX\n", hr); return false; }
    auto sz = item.Size();
    printf("[WGC] item size=%dx%d\n", sz.Width, sz.Height);
    if (sz.Width <= 0 || sz.Height <= 0) return false;

    auto pool = wgcap::Direct3D11CaptureFramePool::CreateFreeThreaded(idev,
        winrt::Windows::Graphics::DirectX::DirectXPixelFormat::B8G8R8A8UIntNormalized, 2, sz);
    auto sess = pool.CreateCaptureSession(item);
    try { sess.IsCursorCaptureEnabled(false); } catch (...) {}
    sess.StartCapture();

    wgcap::Direct3D11CaptureFrame frame{ nullptr };
    for (int i = 0; i < 40; ++i) {
        Sleep(50);
        auto f = pool.TryGetNextFrame();
        if (f) frame = f;
    }
    if (!frame) { printf("[!] no frame\n"); sess.Close(); pool.Close(); return false; }
    Sleep(150);
    for (int i = 0; i < 5; ++i) { auto f = pool.TryGetNextFrame(); if (f) frame = f; Sleep(30); }

    auto access = frame.Surface().as<::Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess>();
    ID3D11Texture2D* raw = nullptr;
    access->GetInterface(__uuidof(ID3D11Texture2D), (void**)&raw);
    ComPtr<ID3D11Texture2D> src; src.Attach(raw);
    D3D11_TEXTURE2D_DESC td{}; src->GetDesc(&td);
    printf("[WGC] tex %ux%u fmt=%d\n", td.Width, td.Height, td.Format);

    D3D11_TEXTURE2D_DESC sd = td;
    sd.Usage = D3D11_USAGE_STAGING; sd.BindFlags = 0;
    sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ; sd.MiscFlags = 0;
    ComPtr<ID3D11Texture2D> st;
    hr = d3d->CreateTexture2D(&sd, nullptr, &st);
    if (FAILED(hr)) { sess.Close(); pool.Close(); return false; }

    ctx->CopyResource(st.Get(), src.Get());
    D3D11_MAPPED_SUBRESOURCE ms{};
    hr = ctx->Map(st.Get(), 0, D3D11_MAP_READ, 0, &ms);
    if (FAILED(hr)) { sess.Close(); pool.Close(); return false; }

    W = int(td.Width); H = int(td.Height);
    out.assign(size_t(W) * H * 4, 0);
    for (int y = 0; y < H; ++y)
        memcpy(out.data() + size_t(y) * W * 4,
               (uint8_t*)ms.pData + y * ms.RowPitch, size_t(W) * 4);
    ctx->Unmap(st.Get(), 0);
    sess.Close(); pool.Close();
    return true;
}

int wmain(int argc, wchar_t** argv) {
    typedef BOOL(WINAPI* SetDpiFn)(DPI_AWARENESS_CONTEXT);
    if (auto p = (SetDpiFn)GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetProcessDpiAwarenessContext"))
        p((DPI_AWARENESS_CONTEXT)(-4));

    if (argc < 3) {
        printf("Uso: wgc_selftest.exe <mode:none|monitor|exclude> <out_prefix>\n");
        return 1;
    }
    if (!_wcsicmp(argv[1], L"none")) g_mode = 0;
    else if (!_wcsicmp(argv[1], L"monitor")) g_mode = WDA_MONITOR;
    else if (!_wcsicmp(argv[1], L"exclude") || !_wcsicmp(argv[1], L"excludefromcapture"))
        g_mode = WDA_EXCLUDEFROMCAPTURE;
    else { printf("modo desconhecido\n"); return 1; }

    static char outBase[MAX_PATH];
    wcstombs_s(nullptr, outBase, MAX_PATH, argv[2], MAX_PATH - 1);

    HRESULT hri = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hri) && hri != RPC_E_CHANGED_MODE) { printf("[!] RoInit 0x%lX\n", hri); return 2; }

    if (!wgcap::GraphicsCaptureSession::IsSupported()) {
        printf("[!] WGC nao suportado\n"); return 3;
    }

    std::thread wt(windowThread);
    while (!g_ready) Sleep(20);
    Sleep(500); // deixa DWM compor
    if (!g_hwnd) { wt.detach(); return 4; }

    std::vector<uint8_t> px; int W = 0, H = 0;
    bool ok = false;
    try { ok = captureWGC(g_hwnd, px, W, H); }
    catch (winrt::hresult_error const& e) {
        printf("[!] hresult 0x%lX msg=%ls\n", e.code().value, e.message().c_str());
    }

    if (ok) {
        std::string p = std::string(outBase) + ".wgc.bmp";
        saveBmp(p.c_str(), px.data(), W, H, W * 4);
        printf("[WGC] saved %s\n", p.c_str());
        verdict("WGC", analyze(px.data(), W, H, W * 4), W, H);
    } else printf("[WGC!] falhou\n");

    // fecha janela e sai
    PostMessage(g_hwnd, WM_CLOSE, 0, 0);
    wt.join();
    RoUninitialize();
    return ok ? 0 : 5;
}
