// BmpCapture.hpp
// Captura o conteudo de uma janela via BitBlt e grava em arquivo .bmp.
// Usado para a prova visual before/after (a janela do proprio app).
#pragma once
#include <windows.h>

class BmpCapture {
public:
    // Captura a janela 'hwnd' e grava em 'path' (UTF-8/ANSI). Lanca
    // std::system_error/std::runtime_error em falha.
    static void captureWindow(HWND hwnd, const char* path);
};
