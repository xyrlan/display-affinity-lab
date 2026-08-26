// BmpCapture.cpp
#include "BmpCapture.hpp"
#include <system_error>
#include <stdexcept>
#include <vector>
#include <string>
#include <cstdio>

namespace {
[[noreturn]] void fail(const char* what) {
    throw std::system_error(static_cast<int>(GetLastError()),
                            std::system_category(), what);
}

// RAII simples para GDI.
struct DcRelease {
    HWND hwnd; HDC dc;
    ~DcRelease() { if (dc) ReleaseDC(hwnd, dc); }
};
} // namespace

void BmpCapture::captureWindow(HWND hwnd, const char* path) {
    RECT rc;
    if (!GetWindowRect(hwnd, &rc)) fail("GetWindowRect");
    const int w = rc.right - rc.left;
    const int h = rc.bottom - rc.top;
    if (w <= 0 || h <= 0) throw std::runtime_error("captureWindow: janela sem area");

    HDC screen = GetDC(nullptr);
    if (!screen) fail("GetDC(NULL)");
    DcRelease screenGuard{nullptr, screen};

    HDC mem = CreateCompatibleDC(screen);
    if (!mem) fail("CreateCompatibleDC");

    HBITMAP bmp = CreateCompatibleBitmap(screen, w, h);
    if (!bmp) { DeleteDC(mem); fail("CreateCompatibleBitmap"); }

    HGDIOBJ old = SelectObject(mem, bmp);
    // Copia a regiao da tela onde a janela esta. Se a janela estiver protegida
    // (0x11), o compositor entrega preto aqui; apos clear, entrega o conteudo.
    BOOL ok = BitBlt(mem, 0, 0, w, h, screen, rc.left, rc.top, SRCCOPY);
    SelectObject(mem, old);
    if (!ok) { DeleteObject(bmp); DeleteDC(mem); fail("BitBlt"); }

    // Monta cabecalhos BMP (24 bpp, bottom-up).
    BITMAPINFOHEADER bih{};
    bih.biSize = sizeof(bih);
    bih.biWidth = w;
    bih.biHeight = h;
    bih.biPlanes = 1;
    bih.biBitCount = 24;
    bih.biCompression = BI_RGB;

    const int stride = ((w * 3 + 3) / 4) * 4; // linhas alinhadas a 4 bytes
    std::vector<uint8_t> pixels(static_cast<size_t>(stride) * h);

    BITMAPINFO bi{};
    bi.bmiHeader = bih;
    if (!GetDIBits(mem, bmp, 0, h, pixels.data(), &bi, DIB_RGB_COLORS)) {
        DeleteObject(bmp); DeleteDC(mem); fail("GetDIBits");
    }

    DeleteObject(bmp);
    DeleteDC(mem);

    BITMAPFILEHEADER bfh{};
    bfh.bfType = 0x4D42; // "BM"
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bfh.bfSize = bfh.bfOffBits + static_cast<DWORD>(pixels.size());

    FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") != 0 || f == nullptr) {
        throw std::runtime_error(std::string("fopen_s falhou: ") + path);
    }
    fwrite(&bfh, sizeof(bfh), 1, f);
    fwrite(&bih, sizeof(bih), 1, f);
    fwrite(pixels.data(), 1, pixels.size(), f);
    fclose(f);
}
