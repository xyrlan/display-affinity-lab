// dxshared_stream — captura continua via DwmGetDxSharedSurface
// Uso: dxshared_stream.exe <hwnd:H|pt|fg|hotkey|needle> <out_dir> [--fps N] [--seconds N] [--save-every N] [--stats-only]
//
// Comportamento:
//   - loop ate <seconds> ou Ctrl+C
//   - a cada tick chama DwmGetDxSharedSurface(hwnd, ...)
//   - se hSurface mudou -> re-abre resource (DWM realoca em resize)
//   - se updId nao mudou -> pula (frame ainda o mesmo)
//   - a cada <save-every>-esimo frame salvo -> grava BMP
//   - imprime stats por segundo (frames capturados, atualizados, FPS efetivo)
//
// Compile: cl /nologo /EHsc /std:c++17 /O2 dxshared_stream.cpp /link ^
//   d3d11.lib dxgi.lib user32.lib gdi32.lib /OUT:dxshared_stream.exe

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
#include <chrono>
#include <atomic>
#include <thread>
#include <csignal>

using Microsoft::WRL::ComPtr;
using clk = std::chrono::steady_clock;

typedef BOOL (WINAPI *DwmGetDxSharedSurface_fn)(
    HWND, HANDLE*, LUID*, ULONG*, ULONG*, ULONGLONG*);

// ---------------- Utils (mesmo do probe) ----------------
struct FindCtx { const wchar_t* needle; DWORD pid; HWND result; int bestArea; };
static BOOL CALLBACK enumProc(HWND h, LPARAM lp) {
    auto* c = (FindCtx*)lp;
    RECT r; GetWindowRect(h, &r);
    int w = r.right - r.left, hh = r.bottom - r.top;
    if (w < 100 || hh < 100) return TRUE;
    if (!IsWindowVisible(h)) return TRUE;
    wchar_t t[512]; GetWindowTextW(h, t, 512);
    DWORD pid = 0; GetWindowThreadProcessId(h, &pid);
    bool m = false;
    if (c->pid) m = (pid == c->pid);
    else if (c->needle) {
        if (t[0] == 0) return TRUE;
        std::wstring s(t), n(c->needle);
        for (auto& x : s) x = towlower(x);
        for (auto& x : n) x = towlower(x);
        m = s.find(n) != std::wstring::npos;
    }
    if (m) {
        int a = w * hh;
        if (a > c->bestArea) { c->bestArea = a; c->result = h; }
    }
    return TRUE;
}
static HWND resolveTarget(const wchar_t* needle) {
    HWND t = nullptr;
    if (wcsncmp(needle, L"hwnd:", 5) == 0) {
        const wchar_t* s = needle + 5;
        if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s += 2;
        t = (HWND)(ULONG_PTR)wcstoull(s, nullptr, 16);
    } else if (wcsncmp(needle, L"pid:", 4) == 0) {
        DWORD pid = _wtoi(needle + 4);
        FindCtx c{ nullptr, pid, nullptr, 0 };
        EnumWindows(enumProc, (LPARAM)&c); t = c.result;
    } else if (!_wcsicmp(needle, L"pt")) {
        printf("[*] 10s pra posicionar mouse. "); for (int i=10;i>0;--i){printf("%d ",i);fflush(stdout);Sleep(1000);}
        printf("\n"); POINT p; GetCursorPos(&p);
        t = WindowFromPoint(p); HWND par;
        while ((par = GetParent(t))) t = par;
    } else if (!_wcsicmp(needle, L"fg")) {
        printf("[*] 10s pra dar foco. "); for (int i=10;i>0;--i){printf("%d ",i);fflush(stdout);Sleep(1000);}
        printf("\n"); t = GetForegroundWindow();
    } else if (!_wcsicmp(needle, L"hotkey")) {
        printf("[*] F2 quando alvo focado.\n");
        RegisterHotKey(nullptr, 1, 0, VK_F2);
        MSG m; while (GetMessage(&m, nullptr, 0, 0) > 0) if (m.message == WM_HOTKEY) { t = GetForegroundWindow(); break; }
        UnregisterHotKey(nullptr, 1);
    } else {
        FindCtx c{ needle, 0, nullptr, 0 };
        EnumWindows(enumProc, (LPARAM)&c); t = c.result;
    }
    return t;
}
static bool saveBmp(const char* p, const uint8_t* bgra, int w, int h, int st) {
    BITMAPFILEHEADER fh{}; BITMAPINFOHEADER ih{};
    fh.bfType = 0x4D42; fh.bfOffBits = sizeof(fh)+sizeof(ih);
    fh.bfSize = fh.bfOffBits + w*h*4;
    ih.biSize = sizeof(ih); ih.biWidth = w; ih.biHeight = -h;
    ih.biPlanes = 1; ih.biBitCount = 32; ih.biCompression = BI_RGB;
    ih.biSizeImage = w*h*4;
    FILE* f=nullptr; fopen_s(&f,p,"wb"); if (!f) return false;
    fwrite(&fh,1,sizeof(fh),f); fwrite(&ih,1,sizeof(ih),f);
    for (int y=0;y<h;++y) fwrite(bgra + y*st, 1, w*4, f);
    fclose(f); return true;
}
struct QuickStats { double mean; int nonZ; int total; };
static QuickStats quickAnalyze(const uint8_t* bgra, int w, int h, int st) {
    // Sub-sample: 1 pixel a cada 8 (linha e coluna) - suficiente pra sanity
    double s = 0; int nz = 0; int total = 0;
    for (int y = 0; y < h; y += 8) {
        const uint8_t* r = bgra + y * st;
        for (int x = 0; x < w; x += 8) {
            uint8_t b = r[x*4], g = r[x*4+1], rr = r[x*4+2];
            if (b || g || rr) ++nz;
            s += 0.299*rr + 0.587*g + 0.114*b;
            ++total;
        }
    }
    return { s / total, nz, total };
}

// ---------------- Signal handling ----------------
static std::atomic<bool> g_stop{ false };
BOOL WINAPI ctrlHandler(DWORD sig) {
    if (sig == CTRL_C_EVENT || sig == CTRL_BREAK_EVENT) {
        g_stop = true; printf("\n[!] Ctrl+C recebido, encerrando...\n"); return TRUE;
    }
    return FALSE;
}

// ---------------- Main ----------------
int wmain(int argc, wchar_t** argv) {
    typedef BOOL(WINAPI* SetDpiFn)(DPI_AWARENESS_CONTEXT);
    if (auto p = (SetDpiFn)GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetProcessDpiAwarenessContext"))
        p((DPI_AWARENESS_CONTEXT)(-4));

    if (argc < 3) {
        printf("Uso: dxshared_stream.exe <hwnd|pt|fg|hotkey|needle> <out_dir> [--fps N] [--seconds N] [--save-every N] [--stats-only]\n");
        return 1;
    }
    const wchar_t* needle = argv[1];
    static char outDir[MAX_PATH];
    wcstombs_s(nullptr, outDir, MAX_PATH, argv[2], MAX_PATH - 1);
    // remove trailing slash
    size_t L = strlen(outDir);
    if (L && (outDir[L-1] == '\\' || outDir[L-1] == '/')) outDir[L-1] = 0;

    int fps = 30, seconds = 5, saveEvery = 30;
    bool statsOnly = false;
    for (int i = 3; i < argc; ++i) {
        if (!_wcsicmp(argv[i], L"--fps") && i+1 < argc) fps = _wtoi(argv[++i]);
        else if (!_wcsicmp(argv[i], L"--seconds") && i+1 < argc) seconds = _wtoi(argv[++i]);
        else if (!_wcsicmp(argv[i], L"--save-every") && i+1 < argc) saveEvery = _wtoi(argv[++i]);
        else if (!_wcsicmp(argv[i], L"--stats-only")) statsOnly = true;
    }
    if (fps < 1) fps = 30;
    if (seconds < 1) seconds = 5;
    if (saveEvery < 1) saveEvery = 1;
    int frameIntervalMs = 1000 / fps;

    SetConsoleCtrlHandler(ctrlHandler, TRUE);

    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    auto pDwmGet = (DwmGetDxSharedSurface_fn)GetProcAddress(u32, "DwmGetDxSharedSurface");
    if (!pDwmGet) { printf("[!] DwmGetDxSharedSurface nao exportado\n"); return 2; }

    HWND target = resolveTarget(needle);
    if (!target || !IsWindow(target)) { printf("[!] HWND invalido\n"); return 3; }

    DWORD tpid = 0; GetWindowThreadProcessId(target, &tpid);
    DWORD wda = 0xDEAD; GetWindowDisplayAffinity(target, &wda);
    wchar_t title[512]; GetWindowTextW(target, title, 512);
    RECT wr; GetWindowRect(target, &wr);
    wprintf(L"[+] Target HWND=%p PID=%lu WDA=%lu title=\"%s\" size=%dx%d\n",
        target, tpid, wda, title, wr.right - wr.left, wr.bottom - wr.top);
    printf("[+] fps=%d seconds=%d save-every=%d stats-only=%d out_dir=%s\n",
        fps, seconds, saveEvery, statsOnly ? 1 : 0, outDir);

    // Primeiro get pra descobrir LUID
    HANDLE hSurface = nullptr;
    LUID luid{}; ULONG fmt = 0, pflags = 0; ULONGLONG updId = 0;
    if (!pDwmGet(target, &hSurface, &luid, &fmt, &pflags, &updId)) {
        printf("[!] primeiro DwmGetDxSharedSurface falhou LE=%lu\n", GetLastError());
        return 4;
    }
    printf("[+] initial hSurface=%p LUID={%08X-%08X} fmt=%u updId=%llu\n",
        hSurface, luid.HighPart, luid.LowPart, fmt, updId);

    // D3D11 device no adapter correto
    ComPtr<IDXGIFactory1> fac;
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&fac))) return 5;
    ComPtr<IDXGIAdapter1> adap;
    for (UINT i = 0; ; ++i) {
        ComPtr<IDXGIAdapter1> a;
        if (fac->EnumAdapters1(i, &a) == DXGI_ERROR_NOT_FOUND) break;
        DXGI_ADAPTER_DESC1 d{}; a->GetDesc1(&d);
        if (d.AdapterLuid.HighPart == luid.HighPart && d.AdapterLuid.LowPart == luid.LowPart) {
            adap = a; break;
        }
    }
    if (!adap) { printf("[!] adapter LUID nao achado\n"); return 6; }

    ComPtr<ID3D11Device> dev; ComPtr<ID3D11DeviceContext> ctx;
    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDevice(adap.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr,
        0, nullptr, 0, D3D11_SDK_VERSION, &dev, &fl, &ctx);
    if (FAILED(hr)) { printf("[!] D3D11CreateDevice 0x%lX\n", hr); return 7; }

    // Cache state
    HANDLE cachedHandle = nullptr;
    ComPtr<ID3D11Texture2D> srcTex;
    ComPtr<ID3D11Texture2D> stagingTex;
    UINT stagingW = 0, stagingH = 0;
    std::vector<uint8_t> pixbuf;

    auto t0 = clk::now();
    auto tLastLog = t0;
    int totalIter = 0;
    int totalUpd = 0;      // frames com updId novo
    int totalSaved = 0;
    int failsHandle = 0;
    int failsMap = 0;
    ULONGLONG lastUpdId = updId - 1;

    while (!g_stop) {
        auto tickStart = clk::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(tickStart - t0).count();
        if (elapsed >= (long long)seconds * 1000) break;
        ++totalIter;

        HANDLE h = nullptr; LUID lu{}; ULONG f = 0, pf = 0; ULONGLONG uid = 0;
        BOOL ok = pDwmGet(target, &h, &lu, &f, &pf, &uid);
        if (!ok || !h) { ++failsHandle; goto sleep_wait; }

        if (h != cachedHandle) {
            // (Re-)abrir shared resource
            srcTex.Reset(); stagingTex.Reset();
            ComPtr<ID3D11Resource> res;
            hr = dev->OpenSharedResource(h, __uuidof(ID3D11Resource), (void**)&res);
            if (FAILED(hr)) { ++failsHandle; cachedHandle = nullptr; goto sleep_wait; }
            hr = res.As(&srcTex);
            if (FAILED(hr) || !srcTex) { ++failsHandle; cachedHandle = nullptr; goto sleep_wait; }
            D3D11_TEXTURE2D_DESC td{}; srcTex->GetDesc(&td);
            D3D11_TEXTURE2D_DESC sd = td;
            sd.Usage = D3D11_USAGE_STAGING; sd.BindFlags = 0;
            sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ; sd.MiscFlags = 0;
            sd.SampleDesc.Count = 1; sd.SampleDesc.Quality = 0;
            hr = dev->CreateTexture2D(&sd, nullptr, &stagingTex);
            if (FAILED(hr)) { ++failsHandle; cachedHandle = nullptr; goto sleep_wait; }
            stagingW = td.Width; stagingH = td.Height;
            pixbuf.assign(size_t(stagingW) * stagingH * 4, 0);
            cachedHandle = h;
            printf("[reopen] handle=%p size=%ux%u fmt=%u\n", h, stagingW, stagingH, td.Format);
        }

        if (uid == lastUpdId) {
            // Frame nao atualizou desde a ultima leitura; opcional: pular
            goto sleep_wait;
        }
        lastUpdId = uid;
        ++totalUpd;

        ctx->CopyResource(stagingTex.Get(), srcTex.Get());
        D3D11_MAPPED_SUBRESOURCE ms{};
        hr = ctx->Map(stagingTex.Get(), 0, D3D11_MAP_READ, 0, &ms);
        if (FAILED(hr)) { ++failsMap; goto sleep_wait; }

        // Copy plano compacto (para saveBmp) - so quando for salvar
        bool willSave = (!statsOnly) && ((totalUpd - 1) % saveEvery == 0);
        if (willSave) {
            for (UINT y = 0; y < stagingH; ++y)
                memcpy(pixbuf.data() + size_t(y) * stagingW * 4,
                       (uint8_t*)ms.pData + y * ms.RowPitch, size_t(stagingW) * 4);
        }
        // Stats rapidas (subsample) - direto do mapped mem, evita copia extra
        QuickStats qs = quickAnalyze((uint8_t*)ms.pData, stagingW, stagingH, ms.RowPitch);
        ctx->Unmap(stagingTex.Get(), 0);

        if (willSave) {
            char path[MAX_PATH];
            snprintf(path, MAX_PATH, "%s\\frame_%05d.bmp", outDir, totalSaved);
            saveBmp(path, pixbuf.data(), stagingW, stagingH, stagingW * 4);
            ++totalSaved;
        }

        // Log por segundo
        auto now = clk::now();
        auto sinceLog = std::chrono::duration_cast<std::chrono::milliseconds>(now - tLastLog).count();
        if (sinceLog >= 1000) {
            printf("[t=%lldms] iter=%d upd=%d saved=%d fails_h=%d fails_m=%d | last mean=%.2f nonz=%d/%d\n",
                elapsed, totalIter, totalUpd, totalSaved, failsHandle, failsMap,
                qs.mean, qs.nonZ, qs.total);
            tLastLog = now;
        }

    sleep_wait:
        auto tickElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(clk::now() - tickStart).count();
        int sleepMs = frameIntervalMs - (int)tickElapsed;
        if (sleepMs > 0) Sleep(sleepMs);
    }

    auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(clk::now() - t0).count();
    double avgFps = totalMs > 0 ? (double)totalUpd * 1000.0 / (double)totalMs : 0;
    printf("\n=========== SUMARIO ============\n");
    printf("  duracao=%.2fs iteracoes=%d upd=%d salvos=%d\n",
        totalMs / 1000.0, totalIter, totalUpd, totalSaved);
    printf("  falhas: handle=%d map=%d\n", failsHandle, failsMap);
    printf("  FPS efetivo (upd/s): %.2f\n", avgFps);
    return 0;
}
