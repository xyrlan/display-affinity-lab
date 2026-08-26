// TestWindow.hpp
// Janela de propriedade do proprio app (RAII). Usada tanto como janela oculta
// de descoberta do offset quanto como janela visivel de demonstracao.
//
// Restricao de escopo: o app SO opera sobre HWNDs criados por esta classe.
// Nunca aceita HWND externo — isso mantem o PoC restrito a janelas proprias.
#pragma once
#include <windows.h>

class TestWindow {
public:
    // visible=false cria janela oculta (discovery); true cria visivel (demo).
    explicit TestWindow(bool visible, const wchar_t* title = L"AffCtl Test");
    ~TestWindow();

    TestWindow(const TestWindow&) = delete;
    TestWindow& operator=(const TestWindow&) = delete;

    HWND hwnd() const { return m_hwnd; }

    // Aplica o modo de DisplayAffinity (WDA_NONE / WDA_MONITOR / WDA_EXCLUDEFROMCAPTURE).
    // Lanca std::system_error se a API falhar.
    void setAffinity(DWORD mode);

    // Drena a fila de mensagens (para a janela pintar/atualizar).
    void pump();

private:
    static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
    static const wchar_t* kClassName;
    static bool s_classRegistered;

    HWND m_hwnd = nullptr;
};
