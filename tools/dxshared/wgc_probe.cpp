// WGC Probe — captura via Windows.Graphics.Capture pra testar bypass do WDA_MONITOR
// Uso: wgc_probe.exe <needle|pid:N|hwnd:H|fg|pt|hotkey> <out_prefix>
// Salva <out>.wgc.bmp (frame do item, cropped ao HWND) + verdict via stats
//
// Compile:
//   cl /nologo /EHsc /std:c++17 /await /O2 wgc_probe.cpp /link ^
//      d3d11.lib dxgi.lib user32.lib gdi32.lib windowsapp.lib /OUT:wgc_probe.exe
//
// Rationale: WGC honra WDA_MONITOR de fábrica → captura fica preta. Se com o hook v9
// no DWM (patch sub_32478) o frame WGC virar real, prova que WGC passa pelo mesmo
// path que PW (bypass parcial). Se continuar preto, WGC usa outro call site.

#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <cwctype>
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
namespace wf = winrt::Windows::Foundation;
namespace wgcap = winrt::Windows::Graphics::Capture;
namespace wgdxd3d = winrt::Windows::Graphics::DirectX::Direct3D11;

// ---------------- Utils (mesmo padrao do dda_probe) ----------------

struct FindCtx { const wchar_t* needle; DWORD pid; HWND result; int bestArea; };
static BOOL CALLBACK enumProc(HWND hwnd, LPARAM lparam) {
    auto* ctx = reinterpret_cast<FindCtx*>(lparam);
    RECT r; GetWindowRect(hwnd, &r);
    int w = r.right - r.left, h = r.bottom - r.top;
    if (w < 100 || h < 100) return TRUE;
    if (!IsWindowVisible(hwnd)) return TRUE;
    wchar_t title[512]; GetWindowTextW(hwnd, title, 512);
    DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
    bool match = false;
    if (ctx->pid) {
        match = (pid == ctx->pid);
    } else if (ctx->needle) {
        if (title[0] == 0) return TRUE;
        std::wstring t(title), n(ctx->needle);
        for (auto& c : t) c = towlower(c);
        for (auto& c : n) c = towlower(c);
        match = t.find(n) != std::wstring::npos;
    }
    if (match) {
        wprintf(L"    candidate HWND=%p PID=%lu title=\"%s\" size=%dx%d\n",
            hwnd, pid, title, w, h);
        int area = w * h;
        if (area > ctx->bestArea) { ctx->bestArea = area; ctx->result = hwnd; }
    }
    return TRUE;
}
static HWND findWindowByTitle(const wchar_t* needle) {
    FindCtx ctx{ needle, 0, nullptr, 0 };
    EnumWindows(enumProc, reinterpret_cast<LPARAM>(&ctx));
    return ctx.result;
}
static HWND findWindowByPid(DWORD pid) {
    FindCtx ctx{ nullptr, pid, nullptr, 0 };
    EnumWindows(enumProc, reinterpret_cast<LPARAM>(&ctx));
    return ctx.result;
}

static bool saveBmp(const char* path, const uint8_t* bgra, int w, int h, int stride) {
    BITMAPFILEHEADER fh{}; BITMAPINFOHEADER ih{};
    fh.bfType = 0x4D42;
    fh.bfOffBits = sizeof(fh) + sizeof(ih);
    fh.bfSize = fh.bfOffBits + w * h * 4;
    ih.biSize = sizeof(ih); ih.biWidth = w; ih.biHeight = -h;
    ih.biPlanes = 1; ih.biBitCount = 32; ih.biCompression = BI_RGB;
    ih.biSizeImage = w * h * 4;
    FILE* f = nullptr; fopen_s(&f, path, "wb");
    if (!f) return false;
    fwrite(&fh, 1, sizeof(fh), f); fwrite(&ih, 1, sizeof(ih), f);
    for (int y = 0; y < h; ++y) fwrite(bgra + y * stride, 1, w * 4, f);
    fclose(f); return true;
}

struct Stats { double mean; double stdev; int blackPct; int nonZeroBytes; };
static Stats analyzeBGRA(const uint8_t* bgra, int w, int h, int stride) {
    double sum = 0, sumSq = 0; int black = 0; int nonZ = 0;
    int64_t n = int64_t(w) * h;
    for (int y = 0; y < h; ++y) {
        const uint8_t* row = bgra + y * stride;
        for (int x = 0; x < w; ++x) {
            uint8_t b = row[x*4], g = row[x*4+1], r = row[x*4+2];
            if (b || g || r) ++nonZ;
            double luma = 0.299*r + 0.587*g + 0.114*b;
            sum += luma; sumSq += luma*luma;
            if (luma < 8) ++black;
        }
    }
    double mean = sum / n;
    double var = sumSq / n - mean * mean;
    return { mean, var > 0 ? sqrt(var) : 0, int(100.0 * black / n), nonZ };
}
static void printVerdict(const char* label, Stats s, int w, int h) {
    printf("[%s] %dx%d mean=%.2f stdev=%.2f black%%=%d nonzero_pixels=%d/%lld\n",
        label, w, h, s.mean, s.stdev, s.blackPct, s.nonZeroBytes, int64_t(w)*h);
    if (s.mean < 4.0 && s.blackPct > 95)
        printf("    -> APARECE PRETO (WDA_MONITOR honrado, ou frame vazio)\n");
    else if (s.mean > 20.0 && s.blackPct < 50)
        printf("    -> FRAME REAL capturado\n");
    else
        printf("    -> AMBIGUO\n");
}

// ---------------- HWND resolver (compartilhado com dda_probe) ----------------

static HWND resolveTarget(const wchar_t* needle) {
    HWND target = nullptr;
    if (wcsncmp(needle, L"pid:", 4) == 0) {
        DWORD pid = _wtoi(needle + 4);
        wprintf(L"[*] Procurando janela por PID %lu:\n", pid);
        target = findWindowByPid(pid);
    } else if (wcsncmp(needle, L"hwnd:", 5) == 0) {
        const wchar_t* s = needle + 5;
        if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s += 2;
        target = (HWND)(ULONG_PTR)wcstoull(s, nullptr, 16);
        wprintf(L"[*] HWND explicito: %p\n", target);
    } else if (!_wcsicmp(needle, L"fg")) {
        printf("[*] 10s pra dar foco na janela desejada. Contagem: ");
        for (int i = 10; i > 0; --i) { printf("%d ", i); fflush(stdout); Sleep(1000); }
        printf("CAPTURA!\n");
        target = GetForegroundWindow();
    } else if (!_wcsicmp(needle, L"pt")) {
        printf("[*] 10s pra posicionar o mouse dentro da janela alvo. Contagem: ");
        for (int i = 10; i > 0; --i) { printf("%d ", i); fflush(stdout); Sleep(1000); }
        printf("CAPTURA!\n");
        POINT p; GetCursorPos(&p);
        target = WindowFromPoint(p);
        HWND parent;
        while ((parent = GetParent(target)) != nullptr) target = parent;
        printf("[*] Cursor em (%d,%d) -> HWND=%p\n", p.x, p.y, target);
    } else if (!_wcsicmp(needle, L"hotkey")) {
        printf("[*] Pressione F2 quando a janela alvo estiver focada.\n");
        RegisterHotKey(nullptr, 1, 0, VK_F2);
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0) > 0) {
            if (msg.message == WM_HOTKEY) { target = GetForegroundWindow(); break; }
        }
        UnregisterHotKey(nullptr, 1);
        printf("[*] F2 -> foreground HWND=%p\n", target);
    } else {
        wprintf(L"[*] Procurando janelas com \"%s\":\n", needle);
        target = findWindowByTitle(needle);
    }
    return target;
}

// ---------------- WGC capture ----------------

// Extrai ID3D11Texture2D de um IDirect3DSurface via IDirect3DDxgiInterfaceAccess
static bool surfaceToTex(const wgdxd3d::IDirect3DSurface& surf, ComPtr<ID3D11Texture2D>& out) {
    auto access = surf.as<::Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess>();
    ID3D11Texture2D* raw = nullptr;
    HRESULT hr = access->GetInterface(__uuidof(ID3D11Texture2D), (void**)&raw);
    if (FAILED(hr)) return false;
    out.Attach(raw);
    return true;
}

// Captura via WGC. Retorna BGRA cropped ao rect_desejado (relativo ao surface do item).
// Se rect for {0,0,0,0}, retorna frame inteiro do item.
static bool captureWGC(HWND hwnd, RECT crop,
                       std::vector<uint8_t>& out, int& outW, int& outH,
                       int& surfW, int& surfH) {
    // 1. D3D11 device
    ComPtr<ID3D11Device> d3d; ComPtr<ID3D11DeviceContext> ctx;
    UINT flags = 0;  // sem DEBUG (evita layer nao instalado)
    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        flags, nullptr, 0, D3D11_SDK_VERSION, &d3d, &fl, &ctx);
    if (FAILED(hr)) { printf("[WGC!] D3D11CreateDevice 0x%lX\n", hr); return false; }

    ComPtr<IDXGIDevice> dxgiDev; d3d.As(&dxgiDev);

    // 2. IDirect3DDevice (WinRT) via interop
    winrt::com_ptr<::IInspectable> insp;
    hr = CreateDirect3D11DeviceFromDXGIDevice(dxgiDev.Get(), insp.put());
    if (FAILED(hr)) { printf("[WGC!] CreateDirect3D11DeviceFromDXGIDevice 0x%lX\n", hr); return false; }
    auto idev = insp.as<wgdxd3d::IDirect3DDevice>();

    // 3. GraphicsCaptureItem via IGraphicsCaptureItemInterop
    auto factory = winrt::get_activation_factory<wgcap::GraphicsCaptureItem,
                        IGraphicsCaptureItemInterop>();
    wgcap::GraphicsCaptureItem item{ nullptr };
    hr = factory->CreateForWindow(hwnd,
        winrt::guid_of<wgcap::GraphicsCaptureItem>(),
        winrt::put_abi(item));
    if (FAILED(hr)) { printf("[WGC!] CreateForWindow 0x%lX (janela minimizada? / sem HWND capture support?)\n", hr); return false; }

    auto sz = item.Size();
    surfW = sz.Width; surfH = sz.Height;
    printf("[WGC] item size=%dx%d\n", surfW, surfH);
    if (surfW <= 0 || surfH <= 0) {
        printf("[WGC!] size invalido\n"); return false;
    }

    // 4. FramePool (free-threaded) + Session
    auto pool = wgcap::Direct3D11CaptureFramePool::CreateFreeThreaded(
        idev, winrt::Windows::Graphics::DirectX::DirectXPixelFormat::B8G8R8A8UIntNormalized,
        2, sz);
    auto session = pool.CreateCaptureSession(item);

    // Sem cursor no frame (opcional). IsCursorCaptureEnabled disponivel desde 1903.
    try { session.IsCursorCaptureEnabled(false); } catch (...) {}
    // Border sem em builds mais novas (2004+). Sem crash se nao suportado.
    try {
        // WinRT does not expose IsBorderRequired na versao 19041, ignorar.
    } catch (...) {}

    session.StartCapture();

    // 5. Bootstrap: aguarda ate ~1.5s por frames
    wgcap::Direct3D11CaptureFrame frame{ nullptr };
    for (int attempt = 0; attempt < 30; ++attempt) {
        Sleep(50);
        auto f = pool.TryGetNextFrame();
        if (f) { frame = f; }
        // Sempre pegue o mais recente disponivel; alguns frames iniciais podem ser pretos
        // ate DWM montar a superficie. Continue tentando.
    }
    if (!frame) {
        printf("[WGC!] nenhum frame chegou em 1.5s\n");
        session.Close(); pool.Close();
        return false;
    }
    // Descarta e pega o proximo depois de um Sleep pra garantir estado estavel
    Sleep(100);
    for (int i = 0; i < 5; ++i) {
        auto f = pool.TryGetNextFrame();
        if (f) frame = f;
        Sleep(30);
    }

    // 6. Extract texture
    ComPtr<ID3D11Texture2D> srcTex;
    if (!surfaceToTex(frame.Surface(), srcTex)) {
        printf("[WGC!] surface->texture falhou\n");
        session.Close(); pool.Close();
        return false;
    }
    D3D11_TEXTURE2D_DESC td{}; srcTex->GetDesc(&td);
    printf("[WGC] frame texture %ux%u fmt=%d\n", td.Width, td.Height, td.Format);

    D3D11_TEXTURE2D_DESC sd = td;
    sd.Usage = D3D11_USAGE_STAGING; sd.BindFlags = 0;
    sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ; sd.MiscFlags = 0;
    ComPtr<ID3D11Texture2D> staging;
    hr = d3d->CreateTexture2D(&sd, nullptr, &staging);
    if (FAILED(hr)) { printf("[WGC!] staging 0x%lX\n", hr); session.Close(); pool.Close(); return false; }

    ctx->CopyResource(staging.Get(), srcTex.Get());
    D3D11_MAPPED_SUBRESOURCE ms{};
    hr = ctx->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &ms);
    if (FAILED(hr)) { printf("[WGC!] map 0x%lX\n", hr); session.Close(); pool.Close(); return false; }

    int fullW = int(td.Width), fullH = int(td.Height);
    int rx, ry, rw, rh;
    if (crop.right == 0 && crop.bottom == 0) {
        rx = 0; ry = 0; rw = fullW; rh = fullH;
    } else {
        rx = crop.left; ry = crop.top;
        rw = crop.right - crop.left; rh = crop.bottom - crop.top;
        if (rx < 0) { rw += rx; rx = 0; }
        if (ry < 0) { rh += ry; ry = 0; }
        if (rx + rw > fullW) rw = fullW - rx;
        if (ry + rh > fullH) rh = fullH - ry;
        if (rw <= 0 || rh <= 0) { rx = 0; ry = 0; rw = fullW; rh = fullH; }
    }
    outW = rw; outH = rh;
    out.assign(size_t(rw) * rh * 4, 0);
    for (int y = 0; y < rh; ++y)
        memcpy(out.data() + size_t(y) * rw * 4,
               (uint8_t*)ms.pData + size_t(ry + y) * ms.RowPitch + rx * 4,
               size_t(rw) * 4);
    ctx->Unmap(staging.Get(), 0);

    session.Close();
    pool.Close();
    return true;
}

// ---------------- Main ----------------

int wmain(int argc, wchar_t** argv) {
    // DPI-aware
    typedef BOOL(WINAPI* SetProcDpiCtxFn)(DPI_AWARENESS_CONTEXT);
    if (auto p = (SetProcDpiCtxFn)GetProcAddress(GetModuleHandleW(L"user32.dll"),
        "SetProcessDpiAwarenessContext")) {
        p((DPI_AWARENESS_CONTEXT)(-4));
    }

    if (argc < 3) {
        printf("Uso: wgc_probe.exe <needle|pid:N|hwnd:H|fg|pt|hotkey> <out_prefix>\n");
        printf("  Salva <out>.wgc.bmp com frame WGC do HWND.\n");
        return 1;
    }
    const wchar_t* needle = argv[1];
    static char outBase[MAX_PATH];
    wcstombs_s(nullptr, outBase, MAX_PATH, argv[2], MAX_PATH - 1);

    HWND target = resolveTarget(needle);
    if (!target || !IsWindow(target)) { printf("[!] HWND invalido\n"); return 2; }

    DWORD tpid = 0; GetWindowThreadProcessId(target, &tpid);
    DWORD aff = 0xDEAD;
    if (GetWindowDisplayAffinity(target, &aff))
        wprintf(L"[+] GetWindowDisplayAffinity: %lu\n", aff);
    wchar_t title[512]; GetWindowTextW(target, title, 512);
    RECT wr; GetWindowRect(target, &wr);
    wprintf(L"\n[+] Target: HWND=%p PID=%lu title=\"%s\" rect=(%d,%d,%d,%d)\n",
        target, tpid, title, wr.left, wr.top, wr.right, wr.bottom);

    // Init WinRT MTA (permite CreateFreeThreaded pool sem message pump)
    HRESULT hri = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hri) && hri != RPC_E_CHANGED_MODE) {
        printf("[!] RoInitialize 0x%lX\n", hri); return 3;
    }

    // Feature check
    if (!wgcap::GraphicsCaptureSession::IsSupported()) {
        printf("[!] Windows.Graphics.Capture NAO suportado nesta build\n");
        RoUninitialize(); return 4;
    }
    printf("[+] WGC IsSupported: yes\n");

    // Captura frame INTEIRO do item (== conteudo do HWND), sem crop
    printf("\n[WGC] Iniciando sessao...\n");
    std::vector<uint8_t> px; int cw = 0, ch = 0, sw = 0, sh = 0;
    RECT noCrop{ 0, 0, 0, 0 };
    bool ok = false;
    try {
        ok = captureWGC(target, noCrop, px, cw, ch, sw, sh);
    } catch (winrt::hresult_error const& e) {
        printf("[WGC!] hresult_error 0x%lX msg=%ls\n", e.code().value, e.message().c_str());
    } catch (std::exception const& e) {
        printf("[WGC!] std::exception %s\n", e.what());
    } catch (...) {
        printf("[WGC!] unknown exception\n");
    }

    if (ok) {
        std::string p = std::string(outBase) + ".wgc.bmp";
        saveBmp(p.c_str(), px.data(), cw, ch, cw * 4);
        printf("[WGC] saved %s\n", p.c_str());
        printVerdict("WGC", analyzeBGRA(px.data(), cw, ch, cw * 4), cw, ch);
    } else {
        printf("[WGC!] captura falhou\n");
    }

    RoUninitialize();
    return ok ? 0 : 5;
}
