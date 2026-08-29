// dxshared_probe — testa DwmGetDxSharedSurface (user32.dll, undocumented)
// como bypass de WDA_MONITOR/EXCLUDEFROMCAPTURE.
//
// Uso: dxshared_probe.exe <needle|hwnd:H|pt|fg|hotkey> <out_prefix>
// Salva <out>.shared.bmp com verdict.
//
// Compile: cl /nologo /EHsc /std:c++17 /O2 dxshared_probe.cpp /link ^
//   d3d11.lib dxgi.lib user32.lib gdi32.lib /OUT:dxshared_probe.exe

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

using Microsoft::WRL::ComPtr;

// Assinatura comum documentada em RE (Windows 10 x64):
// BOOL WINAPI DwmGetDxSharedSurface(
//     HWND hwnd,
//     HANDLE* phSurface,          // shared NT handle to a KMT surface
//     LUID* pAdapterLuid,
//     ULONG* pFmtWindow,
//     ULONG* pPresentFlags,
//     ULONGLONG* pWin32kUpdateId);
typedef BOOL (WINAPI *DwmGetDxSharedSurface_fn)(
    HWND, HANDLE*, LUID*, ULONG*, ULONG*, ULONGLONG*);

// ---------------- HWND resolver ----------------

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
    if (ctx->pid) match = (pid == ctx->pid);
    else if (ctx->needle) {
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
static HWND resolveTarget(const wchar_t* needle) {
    HWND t = nullptr;
    if (wcsncmp(needle, L"pid:", 4) == 0) {
        DWORD pid = _wtoi(needle + 4);
        FindCtx c{ nullptr, pid, nullptr, 0 };
        EnumWindows(enumProc, (LPARAM)&c); t = c.result;
    } else if (wcsncmp(needle, L"hwnd:", 5) == 0) {
        const wchar_t* s = needle + 5;
        if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s += 2;
        t = (HWND)(ULONG_PTR)wcstoull(s, nullptr, 16);
        wprintf(L"[*] HWND=%p\n", t);
    } else if (!_wcsicmp(needle, L"fg")) {
        printf("[*] 10s pra dar foco. "); for (int i=10;i>0;--i){printf("%d ",i);fflush(stdout);Sleep(1000);}
        t = GetForegroundWindow();
    } else if (!_wcsicmp(needle, L"pt")) {
        printf("[*] 10s pra posicionar mouse. "); for (int i=10;i>0;--i){printf("%d ",i);fflush(stdout);Sleep(1000);}
        POINT p; GetCursorPos(&p); t = WindowFromPoint(p);
        HWND par; while ((par = GetParent(t))) t = par;
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

// ---------------- BMP save + stats ----------------
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
struct Stats { double mean, stdev; int blackPct, nonZ; };
static Stats analyze(const uint8_t* p, int w, int h, int st) {
    double s=0,s2=0; int b=0,nz=0; int64_t n=int64_t(w)*h;
    for (int y=0;y<h;++y) { const uint8_t* r=p+y*st;
        for (int x=0;x<w;++x) {
            uint8_t bb=r[x*4],gg=r[x*4+1],rr=r[x*4+2];
            if (bb||gg||rr) ++nz;
            double lu=0.299*rr+0.587*gg+0.114*bb;
            s+=lu; s2+=lu*lu; if (lu<8) ++b;
        }
    }
    double m=s/n; double v=s2/n-m*m;
    return { m, v>0?sqrt(v):0, int(100.0*b/n), nz };
}
static void verdict(const char* lbl, Stats s, int w, int h) {
    printf("[%s] %dx%d mean=%.2f stdev=%.2f black%%=%d nonzero=%d/%lld\n",
        lbl,w,h,s.mean,s.stdev,s.blackPct,s.nonZ,int64_t(w)*h);
    if (s.mean < 4.0 && s.blackPct > 95) printf("    -> PRETO\n");
    else if (s.mean > 20.0 && s.blackPct < 50) printf("    -> FRAME REAL (bypass funcionou)\n");
    else printf("    -> AMBIGUO\n");
}

// ---------------- Main ----------------
int wmain(int argc, wchar_t** argv) {
    typedef BOOL(WINAPI* SetDpiFn)(DPI_AWARENESS_CONTEXT);
    if (auto p = (SetDpiFn)GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetProcessDpiAwarenessContext"))
        p((DPI_AWARENESS_CONTEXT)(-4));

    if (argc < 3) { printf("Uso: dxshared_probe.exe <needle|hwnd:H|pt|fg|hotkey> <out_prefix>\n"); return 1; }
    const wchar_t* needle = argv[1];
    static char outBase[MAX_PATH];
    wcstombs_s(nullptr, outBase, MAX_PATH, argv[2], MAX_PATH-1);

    // Resolve DwmGetDxSharedSurface (por NOME - exportada em user32.dll)
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    auto pDwmGet = (DwmGetDxSharedSurface_fn)GetProcAddress(u32, "DwmGetDxSharedSurface");
    if (!pDwmGet) { printf("[!] DwmGetDxSharedSurface nao exportado nesta build\n"); return 2; }
    printf("[+] DwmGetDxSharedSurface @ %p\n", pDwmGet);

    HWND target = resolveTarget(needle);
    if (!target || !IsWindow(target)) { printf("[!] HWND invalido\n"); return 3; }

    DWORD tpid = 0; GetWindowThreadProcessId(target, &tpid);
    DWORD wda = 0xDEAD; GetWindowDisplayAffinity(target, &wda);
    wchar_t title[512]; GetWindowTextW(target, title, 512);
    RECT wr; GetWindowRect(target, &wr);
    wprintf(L"[+] Target HWND=%p PID=%lu WDA=%lu title=\"%s\" rect=(%d,%d,%d,%d) size=%dx%d\n",
        target, tpid, wda, title, wr.left, wr.top, wr.right, wr.bottom,
        wr.right - wr.left, wr.bottom - wr.top);

    // Chamada undocumented
    HANDLE hSurface = nullptr;
    LUID luid{}; ULONG fmtWin = 0, pflags = 0; ULONGLONG updId = 0;
    SetLastError(0);
    BOOL ok = pDwmGet(target, &hSurface, &luid, &fmtWin, &pflags, &updId);
    DWORD gle = GetLastError();
    printf("[dw] DwmGetDxSharedSurface -> %s (LE=%lu)\n", ok ? "TRUE" : "FALSE", gle);
    printf("    hSurface=%p LUID={%08X-%08X} fmtWin=%u presentFlags=%u updId=%llu\n",
        hSurface, luid.HighPart, luid.LowPart, fmtWin, pflags, updId);
    if (!ok || !hSurface) { printf("[!] shared handle nao obtido\n"); return 4; }

    // Cria D3D11 no adapter certo (LUID match)
    ComPtr<IDXGIFactory1> fac;
    HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&fac);
    if (FAILED(hr)) { printf("[!] CreateDXGIFactory 0x%lX\n", hr); return 5; }
    ComPtr<IDXGIAdapter1> pickAdap;
    for (UINT i = 0; ; ++i) {
        ComPtr<IDXGIAdapter1> a;
        if (fac->EnumAdapters1(i, &a) == DXGI_ERROR_NOT_FOUND) break;
        DXGI_ADAPTER_DESC1 d{}; a->GetDesc1(&d);
        wprintf(L"[dxgi] adap %u: %s LUID={%08X-%08X}\n", i, d.Description, d.AdapterLuid.HighPart, d.AdapterLuid.LowPart);
        if (d.AdapterLuid.HighPart == luid.HighPart && d.AdapterLuid.LowPart == luid.LowPart) {
            pickAdap = a;
        }
    }
    if (!pickAdap) { printf("[!] adapter LUID nao achado\n"); return 6; }

    ComPtr<ID3D11Device> dev; ComPtr<ID3D11DeviceContext> ctx;
    D3D_FEATURE_LEVEL fl;
    hr = D3D11CreateDevice(pickAdap.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr,
        0, nullptr, 0, D3D11_SDK_VERSION, &dev, &fl, &ctx);
    if (FAILED(hr)) { printf("[!] D3D11CreateDevice(adap) 0x%lX\n", hr); return 7; }

    // Abre shared resource — o handle DWM usa KMT (shared handle antigo)
    ComPtr<ID3D11Resource> res;
    // OpenSharedResource espera HANDLE do D3D11 (NT handle ou KMT).
    // DwmGetDxSharedSurface retorna KMT — usar ID3D11Device::OpenSharedResource
    hr = dev->OpenSharedResource(hSurface, __uuidof(ID3D11Resource), (void**)&res);
    if (FAILED(hr) || !res) {
        printf("[!] OpenSharedResource 0x%lX\n", hr);
        return 8;
    }

    ComPtr<ID3D11Texture2D> tex;
    hr = res.As(&tex);
    if (FAILED(hr)) { printf("[!] not Texture2D 0x%lX\n", hr); return 9; }
    D3D11_TEXTURE2D_DESC td{}; tex->GetDesc(&td);
    printf("[tex] %ux%u fmt=%u samples=%u miscFlag=0x%X usage=%u\n",
        td.Width, td.Height, td.Format, td.SampleDesc.Count, td.MiscFlags, td.Usage);

    // Cria staging pra ler
    D3D11_TEXTURE2D_DESC sd = td;
    sd.Usage = D3D11_USAGE_STAGING;
    sd.BindFlags = 0;
    sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    sd.MiscFlags = 0;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    ComPtr<ID3D11Texture2D> stag;
    hr = dev->CreateTexture2D(&sd, nullptr, &stag);
    if (FAILED(hr)) { printf("[!] staging 0x%lX\n", hr); return 10; }

    ctx->CopyResource(stag.Get(), tex.Get());
    D3D11_MAPPED_SUBRESOURCE ms{};
    hr = ctx->Map(stag.Get(), 0, D3D11_MAP_READ, 0, &ms);
    if (FAILED(hr)) { printf("[!] map 0x%lX\n", hr); return 11; }

    int W = int(td.Width), H = int(td.Height);
    std::vector<uint8_t> out(size_t(W) * H * 4, 0);
    // Se formato ja for B8G8R8A8, copiar direto. Se for outro, tratar B/R swap depois.
    for (int y = 0; y < H; ++y)
        memcpy(out.data() + size_t(y) * W * 4,
               (uint8_t*)ms.pData + y * ms.RowPitch, size_t(W) * 4);
    ctx->Unmap(stag.Get(), 0);

    std::string p = std::string(outBase) + ".shared.bmp";
    saveBmp(p.c_str(), out.data(), W, H, W * 4);
    printf("[+] saved %s\n", p.c_str());
    verdict("DwmShared", analyze(out.data(), W, H, W * 4), W, H);

    return 0;
}
